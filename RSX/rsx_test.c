#include "common.h"
#include "aes_kat.h"
#include "sha3_kat.h"
#include <stdio.h>

/* AES-NI Detection */

#if defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(__cpuid)

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	__cpuid(info, 1);

	if (info[2] != 0)
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#elif defined(__GNUC__)

#include <cpuid.h>
#pragma GCC target ("ssse3")
#pragma GCC target ("sse4.1")
#pragma GCC target ("aes")
#include <x86intrin.h>

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	if (__get_cpuid(1, &info[0], &info[1], &info[2], &info[3]))
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#else

static int has_aes_ni()
{
	return 0;
}

#endif

/**
* \wait for input
*/
void get_response()
{
	getwchar();
}

/**
* \brief Test the AES implementation with vectors from Fips197 and 
* new vectors for the extended modes RSX256 and RSX512
*/
void rsx_test_run()
{
	if (aes128_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 CBC KAT test. \n \n");
	}

	if (aes256_cbc_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 CBC KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 CBC KAT test. \n \n");
	}

	if (aes128_ctr_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 CTR KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 CTR KAT test. \n \n");
	}

	if (aes256_ctr_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 CTR KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 CTR KAT test. \n \n");
	}

	if (aes128_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES128 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES128 ECB KAT test. \n \n");
	}

	if (aes256_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the AES256 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the AES256 ECB KAT test. \n \n");
	}

	if (rsx256_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the RSX256 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RSX256 ECB KAT test. \n \n");
	}

	if (rsx512_ecb_kat_test() == true)
	{
		printf_s("Success! Passed the RSX512 ECB KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RSX512 ECB KAT test. \n \n");
	}
}

/**
* \brief Run the SHA3, SHAKE, cSHAKE, simple cSHAKE, and KMAC KAT tests
*/
void sha3_test_run()
{
	if (sha3_256_kat_test() == true)
	{
		printf_s("Success! passed sha3-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed sha3-256 known answer tests \n");
	}

	if (sha3_512_kat_test() == true)
	{
		printf_s("Success! passed sha3-512 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed sha3-512 known answer tests \n");
	}

	if (shake_128_kat_test() == true)
	{
		printf_s("Success! passed shake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed shake-128 known answer tests \n");
	}

	if (shake_256_kat_test() == true)
	{
		printf_s("Success! passed shake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed shake-256 known answer tests \n");
	}

	if (cshake_128_kat_test() == true)
	{
		printf_s("Success! passed cshake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed cshake-128 known answer tests \n");
	}

	if (cshake_256_kat_test() == true)
	{
		printf_s("Success! passed cshake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed cshake-256 known answer tests \n");
	}

	if (cshake_simple_128_kat_test() == true)
	{
		printf_s("Success! passed simple cshake-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed simple cshake-128 known answer tests \n");
	}

	if (cshake_simple_256_kat_test() == true)
	{
		printf_s("Success! passed simple cshake-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed simple cshake-256 known answer tests \n");
	}

	if (kmac_128_kat_test() == true)
	{
		printf_s("Success! passed kmac-128 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed kmac-128 known answer tests \n");
	}

	if (kmac_256_kat_test() == true)
	{
		printf_s("Success! passed kmac-256 known answer tests \n");
	}
	else
	{
		printf_s("Failure! failed kmac-256 known answer tests \n");
	}
}

int main()
{
	int valid = 1;

	if (has_aes_ni() == 1)
	{
		printf_s("AES-NI is available on this system. \n");
#if !defined(RSX_AESNI_ENABLED)
		printf_s("Add the RSX_AESNI_ENABLED flag to the preprocessor definitions to test AES-NI implementation. \n");
#endif
		printf_s("\n");
	}
	else
	{
		printf_s("AES-NI was not detected on this system. \n");
#if defined(RSX_AESNI_ENABLED)
		printf_s("Remove the RSX_AESNI_ENABLED flag from the preprocessor definitions to test the standard implementation. \n");
		printf_s("The test can not proceed! Press any key to close..");
		ret = get_response();
		valid = 0;
#endif
	}

	if (valid == 1)
	{
		printf("*** Testing SHA3 digests, SHAKE, and cSHAKE implementations *** \n");
		sha3_test_run();
		printf("\n");

		printf_s("*** Test using the NIST SP800-38a Known Answer Tests *** \n");
		printf_s("\n");
		rsx_test_run();
		printf_s("\n");

		printf_s("\n");
		printf_s("Completed! Press any key to close..");
		get_response();
	}

    return 0;
}

