/* do PSK operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2015 Antony Antony <antony@phenome.org>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "keys.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"

#include <nss.h>
#include <pk11pub.h>

static const char psk_key_pad_str[] = "Key Pad for IKEv2";  /* 4306  2:15 */
static const size_t psk_key_pad_str_len = 17;                  /* sizeof(psk_key_pad_str); -1 */

static bool ikev2_calculate_psk_sighash(struct state *st,
					enum original_role role,
					unsigned char *idhash,
					chunk_t firstpacket,
					unsigned char *signed_octets)
{
	const chunk_t *nonce;
	const char    *nonce_name;
	const struct connection *c = st->st_connection;
	const chunk_t *pss = &empty_chunk;
	const size_t hash_len =  st->st_oakley.prf_hasher->hash_digest_len;

	if (!(c->policy & POLICY_AUTH_NULL)) {
		pss = get_preshared_secret(c);
		if (pss == NULL) {
			libreswan_log("No matching PSK found for connection:%s",
			      st->st_connection->name);
			return FALSE; /* failure: no PSK to use */
		}
		DBG(DBG_PRIVATE, DBG_dump_chunk("User PSK:", *pss));
	} else {
		/*
		 * draft-ietf-ipsecme-ikev2-null-auth-02
		 *
		 * When using the NULL Authentication Method, the
		 * content of the AUTH payload is computed using the
		 * syntax of pre-shared secret authentication,
		 * described in Section 2.15 of [RFC7296].  The values
		 * SK_pi and SK_pr are used as shared secrets for the
		 * content of the AUTH payloads generated by the
		 * initiator and the responder respectively.
		 *
		 * We have SK_pi/SK_pr as PK11SymKey in st_skey_pi_nss
		 * and st_skey_pr_nss
		 */
		passert(st->hidden_variables.st_skeyid_calculated);

		/*
		 * This is wrong as role - we need to role for THIS exchange
		 * But verify calls this routine with the role inverted, so we
		 * cannot juse st->st_state either.
		 */
		if (role == ORIGINAL_INITIATOR) {
			/* we are sending initiator, or verifying responder */
			pss = &st->st_skey_chunk_SK_pi;
		} else {
			/* we are verifying initiator, or sending responder */
			pss = &st->st_skey_chunk_SK_pr;
		}
		 DBG(DBG_PRIVATE, DBG_dump_chunk("AUTH_NULL PSK:", *pss));
	}

	/*
	 * RFC 4306 2.15:
	 * AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)
	 */

	/* calculate inner prf */
	PK11SymKey *prf_psk;
	{
		struct crypt_prf *prf =
			crypt_prf_init("<prf-psk> = prf(<psk>,\"Key Pad for IKEv2\")",
				       st->st_oakley.prf_hasher,
				       st->st_shared_nss/*scratch*/);
		crypt_prf_init_chunk("shared secret", prf, *pss);
		crypt_prf_update(prf);
		crypt_prf_update_bytes(psk_key_pad_str/*name*/, prf,
				       psk_key_pad_str, psk_key_pad_str_len);
		prf_psk = crypt_prf_final(prf);
	}

	/* decide nonce based on the role */
	if (role == ORIGINAL_INITIATOR) {
		/* on initiator, we need to hash responders nonce */
		nonce = &st->st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
	} else {
		nonce = &st->st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
	}

	/* calculate outer prf */
	{
		struct crypt_prf *prf =
			crypt_prf_init("<signed-octets> = prf(<prf-psk>, <msg octets>)",
				       st->st_oakley.prf_hasher,
				       st->st_shared_nss /*scratch*/);
		crypt_prf_init_symkey("<prf-psk>", prf, prf_psk);
		/*
		 * For the responder, the octets to be signed start
		 * with the first octet of the first SPI in the header
		 * of the second message and end with the last octet
		 * of the last payload in the second message.
		 * Appended to this (for purposes of computing the
		 * signature) are the initiator's nonce Ni (just the
		 * value, not the payload containing it), and the
		 * value prf(SK_pr,IDr') where IDr' is the responder's
		 * ID payload excluding the fixed header.  Note that
		 * neither the nonce Ni nor the value prf(SK_pr,IDr')
		 * are transmitted.
		 */
		crypt_prf_update(prf);
		crypt_prf_update_chunk("first-packet", prf, firstpacket);
		crypt_prf_update_chunk("nonce", prf, *nonce);
		crypt_prf_update_bytes("hash", prf, idhash, hash_len);
		crypt_prf_final_bytes(prf, signed_octets, hash_len);
	}
	free_any_symkey("<prf-psk>", &prf_psk);

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	    DBG_dump_chunk(nonce_name, *nonce);
	    DBG_dump("idhash", idhash, hash_len));

	return TRUE;
}

bool ikev2_calculate_psk_auth(struct state *st,
			      enum original_role role,
			      unsigned char *idhash,
			      pb_stream *a_pbs)
{
	unsigned int hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
	unsigned char signed_octets[hash_len];

	if (!ikev2_calculate_psk_sighash(st, role, idhash,
					 st->st_firstpacket_me,
					 signed_octets))
		return FALSE;

	DBG(DBG_PRIVATE,
	    DBG_dump("PSK auth octets", signed_octets, hash_len ));

	if (!out_raw(signed_octets, hash_len, a_pbs, "PSK auth"))
		return FALSE;

	return TRUE;
}

stf_status ikev2_verify_psk_auth(struct state *st,
				 enum original_role role,
				 unsigned char *idhash,
				 pb_stream *sig_pbs)
{
	unsigned int hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
	unsigned char calc_hash[hash_len];
	size_t sig_len = pbs_left(sig_pbs);

	enum original_role invertrole;

	invertrole = (role == ORIGINAL_INITIATOR ? ORIGINAL_RESPONDER : ORIGINAL_INITIATOR);

	if (sig_len != hash_len) {
		libreswan_log("negotiated prf: %s ",
			      st->st_oakley.prf_hasher->common.name);
		libreswan_log(
			"I2 hash length:%lu does not match with PRF hash len %lu",
			(long unsigned) sig_len,
			(long unsigned) hash_len);
		return STF_FAIL;
	}

	if (!ikev2_calculate_psk_sighash(st, invertrole, idhash,
					 st->st_firstpacket_him, calc_hash))
		return STF_FAIL;

	DBG(DBG_PRIVATE,
	    DBG_dump("Received PSK auth octets", sig_pbs->cur, sig_len);
	    DBG_dump("Calculated PSK auth octets", calc_hash, hash_len));

	if (memeq(sig_pbs->cur, calc_hash, hash_len) ) {
		return STF_OK;
	} else {
		libreswan_log("AUTH mismatch: Received AUTH != computed AUTH");
		return STF_FAIL;
	}
}
