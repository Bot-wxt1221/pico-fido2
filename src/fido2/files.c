/*
 * This file is part of the Pico FIDO2 distribution (https://github.com/polhenarejos/pico-fido2).
 * Copyright (c) 2025 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "fido/files.h"
#undef _FILES_H_
#include "openpgp/files.h"

extern const uint8_t openpgp_aid[];
extern const uint8_t openpgp_aid_full[];

#define ACL_NONE    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
#define ACL_ALL     { 0 }
#define ACL_RO      { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 }
#define ACL_RW      { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define ACL_R_WP    { 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0x00 }
#define ACL_WP      { 0xff, 0xff, 0xff, 0xff, 0x90, 0x90, 0xff }

extern int parse_ch_data(const file_t *f, int mode);
extern int parse_sec_tpl(const file_t *f, int mode);
extern int parse_ch_cert(const file_t *f, int mode);
extern int parse_gfm(const file_t *f, int mode);
extern int parse_fp(const file_t *f, int mode);
extern int parse_cafp(const file_t *f, int mode);
extern int parse_ts(const file_t *f, int mode);
extern int parse_keyinfo(const file_t *f, int mode);
extern int parse_algoinfo(const file_t *f, int mode);
extern int parse_app_data(const file_t *f, int mode);
extern int parse_discrete_do(const file_t *f, int mode);
extern int parse_pw_status(const file_t *f, int mode);
extern int piv_parse_discovery(const file_t *f);

uint8_t historical_bytes[] = {
    10, 0,
    0x00,
    0x31, 0x84,         /* Full DF name, GET DATA, MF */
    0x73,
    0x80, 0x01, 0xC0,   /* Full DF name */
    /* 1-byte */
    /* Command chaining, No extended Lc and Le */
    0x05,
    0x90, 0x00          /* Status info */
};

uint8_t extended_capabilities[] = {
    10, 0,
    0x77,           /*
                     * No Secure Messaging supported
                     * GET CHALLENGE supported
                     * Key import supported
                     * PW status byte can be put
                     * No private_use_DO
                     * Algorithm attrs are changable
                     * ENC/DEC with AES
                     * KDF-DO available
                     */
    0,        /* Secure Messaging Algorithm: N/A (TDES=0, AES=1) */
    0x00, 128,      /* Max size of GET CHALLENGE */
    0x08, 0x00,   /* max. length of cardholder certificate (2KiB) */
    0x00, 0xff,
    0x00, 0x1
};

uint8_t feature_mngmnt[] = {
    3, 0,
    0x81, 0x01, 0x20,
};

uint8_t exlen_info[] = {
    8, 0,
    0x2, 0x2, 0x07, 0xff,
    0x2, 0x2, 0x08, 0x00,
};

file_t file_entries[] = {
    { .fid = 0x3f00, .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = { 0 } }, // MF
    { .fid = EF_KEY_DEV, .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // Device Key
    { .fid = EF_KEY_DEV_ENC, .parent = 0, .name = NULL,.type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // Device Key Enc
    { .fid = EF_EE_DEV,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // End Entity Certificate Device
    { .fid = EF_EE_DEV_EA,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // End Entity Enterprise Attestation Certificate
    { .fid = EF_COUNTER,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // Global counter
    { .fid = EF_PIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // PIN
    { .fid = EF_AUTHTOKEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // AUTH TOKEN
    { .fid = EF_PAUTHTOKEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // PERSISTENT AUTH TOKEN
    { .fid = EF_MINPINLEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // MIN PIN LENGTH
    { .fid = EF_OPTS,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // Global options
    { .fid = EF_LARGEBLOB,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // Large Blob
    { .fid = EF_OTP_PIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } },
    { .fid = EF_PIN_ADMIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = { 0xff } }, // ADMIN PIN
    { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_NOT_KNOWN, .data = NULL, .ef_structure = 0, .acl = { 0 } }  //end                                                                                  //end
};

const file_t *MF = &file_entries[0];
const file_t *file_openpgp = &file_entries[sizeof(file_entries) / sizeof(file_t) - 2];
const file_t *file_last = &file_entries[sizeof(file_entries) / sizeof(file_t) - 1];

file_t *ef_keydev = NULL;
file_t *ef_certdev = NULL;
file_t *ef_counter = NULL;
file_t *ef_pin = NULL;
file_t *ef_pin_admin = NULL;
file_t *ef_authtoken = NULL;
file_t *ef_keydev_enc = NULL;
file_t *ef_largeblob = NULL;
