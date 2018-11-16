const unsigned int packet1_len = 540;
const unsigned char packet1[] = {
	0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x02, 0x18, /* ....E... */
	0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, /* ....@... */
	0xc0, 0x01, 0x02, 0x2d, 0xc0, 0x01, 0x02, 0x17, /* ...-.... */
	0x01, 0xf4, 0x01, 0xf4, 0x02, 0x04, 0x00, 0x00, /* ........ */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* ........ */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
	0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, /* ! "..... */
	0x00, 0x00, 0x01, 0xfc, 0x22, 0x80, 0x00, 0xf4, /* ...."... */
	0x02, 0x00, 0x00, 0x28, 0x01, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0c, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05, /* ........ */
	0x02, 0x00, 0x00, 0x28, 0x02, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0c, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05, /* ........ */
	0x02, 0x00, 0x00, 0x28, 0x03, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05, /* ........ */
	0x02, 0x00, 0x00, 0x28, 0x04, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05, /* ........ */
	0x02, 0x00, 0x00, 0x28, 0x05, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02, /* ........ */
	0x00, 0x00, 0x00, 0x28, 0x06, 0x01, 0x00, 0x04, /* ...(.... */
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, /* ........ */
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01, /* ........ */
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02, /* ........ */
	0x28, 0x00, 0x00, 0xc8, 0x00, 0x05, 0x00, 0x00, /* (....... */
	0xff, 0xbc, 0x6a, 0x92, 0xa6, 0xb9, 0x55, 0x9b, /* ..j...U. */
	0x05, 0xfa, 0x96, 0xa7, 0xa4, 0x35, 0x07, 0xb4, /* .....5.. */
	0xc1, 0xe1, 0xc0, 0x86, 0x1a, 0x58, 0x71, 0xd9, /* .....Xq. */
	0xba, 0x73, 0xa1, 0x63, 0x11, 0x37, 0x88, 0xc0, /* .s.c.7.. */
	0xde, 0xbb, 0x39, 0x79, 0xe7, 0xff, 0x0c, 0x52, /* ..9y...R */
	0xb4, 0xce, 0x60, 0x50, 0xeb, 0x05, 0x36, 0x9e, /* ..`P..6. */
	0xa4, 0x30, 0x0d, 0x2b, 0xff, 0x3b, 0x1b, 0x29, /* .0.+.;.) */
	0x9f, 0x3b, 0x80, 0x2c, 0xcb, 0x13, 0x31, 0x8c, /* .;.,..1. */
	0x2a, 0xb9, 0xe3, 0xb5, 0x62, 0x7c, 0xb4, 0xb3, /* *...b|.. */
	0x5e, 0xb9, 0x39, 0x98, 0x20, 0x76, 0xb5, 0x7c, /* ^.9. v.| */
	0x05, 0x0d, 0x7b, 0x35, 0xc3, 0xc5, 0xc7, 0xcc, /* ..{5.... */
	0x8c, 0x0f, 0xea, 0xb7, 0xb6, 0x4a, 0x7d, 0x7b, /* .....J}{ */
	0x6b, 0x8f, 0x6b, 0x4d, 0xab, 0xf4, 0xac, 0x40, /* k.kM...@ */
	0x6d, 0xd2, 0x01, 0x26, 0xb9, 0x0a, 0x98, 0xac, /* m..&.... */
	0x76, 0x6e, 0xfa, 0x37, 0xa7, 0x89, 0x0c, 0x43, /* vn.7...C */
	0x94, 0xff, 0x9a, 0x77, 0x61, 0x5b, 0x58, 0xf5, /* ...wa[X. */
	0x2d, 0x65, 0x1b, 0xbf, 0xa5, 0x8d, 0x2a, 0x54, /* -e....*T */
	0x9a, 0xf8, 0xb0, 0x1a, 0xa4, 0xbc, 0xa3, 0xd7, /* ........ */
	0x62, 0x42, 0x66, 0x63, 0xb1, 0x55, 0xd4, 0xeb, /* bBfc.U.. */
	0xda, 0x9f, 0x60, 0xa6, 0xa1, 0x35, 0x73, 0xe6, /* ..`..5s. */
	0xa8, 0x88, 0x13, 0x5c, 0xdc, 0x67, 0x3d, 0xd4, /* ...\.g=. */
	0x83, 0x02, 0x99, 0x03, 0xf3, 0xa9, 0x0e, 0xca, /* ........ */
	0x23, 0xe1, 0xec, 0x1e, 0x27, 0x03, 0x31, 0xb2, /* #...'.1. */
	0xd0, 0x50, 0xf4, 0xf7, 0x58, 0xf4, 0x99, 0x27, /* .P..X..' */
	0x2b, 0x80, 0x00, 0x14, 0xb5, 0xce, 0x84, 0x19, /* +....... */
	0x09, 0x5c, 0x6e, 0x2b, 0x6b, 0x62, 0xd3, 0x05, /* .\n+kb.. */
	0x53, 0x05, 0xb3, 0xc4, 0x00, 0x00, 0x00, 0x10, /* S....... */
	0x4f, 0x45, 0x70, 0x6c, 0x75, 0x74, 0x6f, 0x75, /* OEplutou */
	0x6e, 0x69, 0x74, 0x30,                         /* nit0     */
	0
};

