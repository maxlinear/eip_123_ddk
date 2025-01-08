/* cf_cal_cm-v2.h
 *
 * This configuration file controls which CAL API functions are included in
 * the build and which CAL implementation provides it: stub, cm, pk or sw.
 *
 * This tailored CAL configuration file is for use with the EIP-123 Crypto
 * Module, which provides Hash, Crypto, MAC, Random and Asset Store services
 * through CAL-CM.
 */

/*****************************************************************************
* Copyright (c) 2010-2015 INSIDE Secure B.V. All Rights Reserved.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*****************************************************************************/

// enable each CAL implementation that is used
// this is used for Init, ReadVersion and FeatureMatrix
//#define SFZCRYPTO_CF_USE__SW
#define SFZCRYPTO_CF_USE__CM
//#define SFZCRYPTO_CF_USE__PK

/*----------------------------------------------------
 *   NOTE: Below, select ONLY ONE option in each block
 *----------------------------------------------------
 */

#undef  SFZCRYPTO_CF_HASH_DATA__REMOVE
#undef  SFZCRYPTO_CF_HASH_DATA__STUB
#undef  SFZCRYPTO_CF_HASH_DATA__SW
#define SFZCRYPTO_CF_HASH_DATA__CM

#undef  SFZCRYPTO_CF_HMAC_DATA__REMOVE
#undef  SFZCRYPTO_CF_HMAC_DATA__STUB
#undef  SFZCRYPTO_CF_HMAC_DATA__SW
#define SFZCRYPTO_CF_HMAC_DATA__CM

#undef  SFZCRYPTO_CF_SYMM_CRYPT__REMOVE
#undef  SFZCRYPTO_CF_SYMM_CRYPT__STUB
#undef  SFZCRYPTO_CF_SYMM_CRYPT__SW
#define SFZCRYPTO_CF_SYMM_CRYPT__CM

#undef  SFZCRYPTO_CF_CIPHER_MAC_DATA__REMOVE
#undef  SFZCRYPTO_CF_CIPHER_MAC_DATA__STUB
#undef  SFZCRYPTO_CF_CIPHER_MAC_DATA__SW
#define SFZCRYPTO_CF_CIPHER_MAC_DATA__CM

#undef  SFZCRYPTO_CF_CPRM_C2_DERIVE__REMOVE
#undef  SFZCRYPTO_CF_CPRM_C2_DERIVE__STUB
#undef  SFZCRYPTO_CF_CPRM_C2_DERIVE__SW
#define SFZCRYPTO_CF_CPRM_C2_DERIVE__CM

#undef  SFZCRYPTO_CF_CPRM_C2_DEVICEKEYOBJECT_ROWNR_GET__REMOVE
#undef  SFZCRYPTO_CF_CPRM_C2_DEVICEKEYOBJECT_ROWNR_GET__STUB
#undef  SFZCRYPTO_CF_CPRM_C2_DEVICEKEYOBJECT_ROWNR_GET__SW
#define SFZCRYPTO_CF_CPRM_C2_DEVICEKEYOBJECT_ROWNR_GET__CM

#undef  SFZCRYPTO_CF_MULTI2_CONFIGURE__REMOVE
#undef  SFZCRYPTO_CF_MULTI2_CONFIGURE__STUB
#undef  SFZCRYPTO_CF_MULTI2_CONFIGURE__SW
#define SFZCRYPTO_CF_MULTI2_CONFIGURE__CM

#undef  SFZCRYPTO_CF_RANDOM_RESEED__REMOVE
#undef  SFZCRYPTO_CF_RANDOM_RESEED__STUB
#undef  SFZCRYPTO_CF_RANDOM_RESEED__SW
#define SFZCRYPTO_CF_RANDOM_RESEED__CM
#undef  SFZCRYPTO_CF_RANDOM_RESEED__PK

#undef  SFZCRYPTO_CF_RAND_DATA__REMOVE
#undef  SFZCRYPTO_CF_RAND_DATA__STUB
#undef  SFZCRYPTO_CF_RAND_DATA__SW
#define SFZCRYPTO_CF_RAND_DATA__CM
#undef  SFZCRYPTO_CF_RAND_DATA__PK

#undef  SFZCRYPTO_CF_RANDOM_SELFTEST__REMOVE
#undef  SFZCRYPTO_CF_RANDOM_SELFTEST__STUB
#define SFZCRYPTO_CF_RANDOM_SELFTEST__CM
#undef  SFZCRYPTO_CF_RANDOM_SELFTEST__PK

#undef  SFZCRYPTO_CF_NOP__REMOVE
#undef  SFZCRYPTO_CF_NOP__STUB
#undef  SFZCRYPTO_CF_NOP__SW
#define SFZCRYPTO_CF_NOP__CM

#undef  SFZCRYPTO_CF_NVM_PUBLICDATA_READ__REMOVE
#undef  SFZCRYPTO_CF_NVM_PUBLICDATA_READ__STUB
#undef  SFZCRYPTO_CF_NVM_PUBLICDATA_READ__SW
#define SFZCRYPTO_CF_NVM_PUBLICDATA_READ__CM

#undef  SFZCRYPTO_CF_ASSET_ALLOC__REMOVE
#undef  SFZCRYPTO_CF_ASSET_ALLOC__STUB
#undef  SFZCRYPTO_CF_ASSET_ALLOC__SW
#define SFZCRYPTO_CF_ASSET_ALLOC__CM

#undef  SFZCRYPTO_CF_ASSET_ALLOC_TEMPORARY__REMOVE
#undef  SFZCRYPTO_CF_ASSET_ALLOC_TEMPORARY__STUB
#undef  SFZCRYPTO_CF_ASSET_ALLOC_TEMPORARY__SW
#define SFZCRYPTO_CF_ASSET_ALLOC_TEMPORARY__CM

#undef  SFZCRYPTO_CF_ASSET_FREE__REMOVE
#undef  SFZCRYPTO_CF_ASSET_FREE__STUB
#undef  SFZCRYPTO_CF_ASSET_FREE__SW
#define SFZCRYPTO_CF_ASSET_FREE__CM

#undef  SFZCRYPTO_CF_ASSET_SEARCH__REMOVE
#undef  SFZCRYPTO_CF_ASSET_SEARCH__STUB
#undef  SFZCRYPTO_CF_ASSET_SEARCH__SW
#define SFZCRYPTO_CF_ASSET_SEARCH__CM

#undef  SFZCRYPTO_CF_ASSET_GET_ROOT_KEY__REMOVE
#undef  SFZCRYPTO_CF_ASSET_GET_ROOT_KEY__STUB
#undef  SFZCRYPTO_CF_ASSET_GET_ROOT_KEY__SW
#define SFZCRYPTO_CF_ASSET_GET_ROOT_KEY__CM

#undef  SFZCRYPTO_CF_ASSET_LOAD_GENERIC__REMOVE
#undef  SFZCRYPTO_CF_ASSET_LOAD_GENERIC__STUB
#undef  SFZCRYPTO_CF_ASSET_LOAD_GENERIC__SW
#define SFZCRYPTO_CF_ASSET_LOAD_GENERIC__CM

#undef  SFZCRYPTO_CF_ASSET_IMPORT__REMOVE
#undef  SFZCRYPTO_CF_ASSET_IMPORT__STUB
#undef  SFZCRYPTO_CF_ASSET_IMPORT__SW
#define SFZCRYPTO_CF_ASSET_IMPORT__CM

#undef  SFZCRYPTO_CF_ASSET_DERIVE__REMOVE
#undef  SFZCRYPTO_CF_ASSET_DERIVE__STUB
#undef  SFZCRYPTO_CF_ASSET_DERIVE__SW
#define SFZCRYPTO_CF_ASSET_DERIVE__CM

#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY__REMOVE
#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY__STUB
#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY__SW
#define SFZCRYPTO_CF_ASSET_LOAD_KEY__CM

#undef  SFZCRYPTO_CF_ASSET_GEN_KEY__REMOVE
#undef  SFZCRYPTO_CF_ASSET_GEN_KEY__STUB
#undef  SFZCRYPTO_CF_ASSET_GEN_KEY__SW
#define SFZCRYPTO_CF_ASSET_GEN_KEY__CM

#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY_AND_WRAP__REMOVE
#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY_AND_WRAP__STUB
#undef  SFZCRYPTO_CF_ASSET_LOAD_KEY_AND_WRAP__SW
#define SFZCRYPTO_CF_ASSET_LOAD_KEY_AND_WRAP__CM

#undef  SFZCRYPTO_CF_ASSET_GEN_KEY_AND_WRAP__REMOVE
#undef  SFZCRYPTO_CF_ASSET_GEN_KEY_AND_WRAP__STUB
#undef  SFZCRYPTO_CF_ASSET_GEN_KEY_AND_WRAP__SW
#define SFZCRYPTO_CF_ASSET_GEN_KEY_AND_WRAP__CM

#undef  SFZCRYPTO_CF_AUNLOCK__REMOVE
#undef  SFZCRYPTO_CF_AUNLOCK__STUB
#define SFZCRYPTO_CF_AUNLOCK__CM

/* end of file cf_cal_cm-v2.h */
