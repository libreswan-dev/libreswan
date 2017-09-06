/* Output a formatted debug string, for libreswan
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Andrew Cagney
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
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"

int lswlog_dbg(const char *message, ...)
{
	char buf[LOG_WIDTH];
	va_list args;
	va_start(args, message);
	vsnprintf(buf, sizeof(buf), message, args);
	va_end(args);

	lswlog_dbg_raw(buf, sizeof(buf));
	return 0;
}