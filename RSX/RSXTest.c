#include "fips197_test.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/**
* \brief Get a char from console input.
* \return Returns one user input char
*/
char get_response()
{
	return getchar();
}

/**
* \brief Test the AES implementation with vectors from Fips197 and 
* new vectors for the extended modes RSX256 and RSX512
*/
void rsx_test_run()
{
	if (aes_128_kat_test() == FIPS197_STATUS_SUCCESS)
	{
		printf("Success! Passed the AES128 KAT test. \n");
	}
	else
	{
		printf("Failure! Failed the AES128 KAT test. \n \n");
	}

	if (aes_256_kat_test() == FIPS197_STATUS_SUCCESS)
	{
		printf("Success! Passed the AES256 KAT test. \n");
	}
	else
	{
		printf("Failure! Failed the AES256 KAT test. \n \n");
	}
}

int main()
{
	printf("*** Test using the Fips197 Known Answer Tests *** \n");
	printf("\n");
	rsx_test_run();
	printf("\n");

	printf("\n");
	printf("Completed! Press any key to close..");
	get_response();

	rsx_test_run();
    return 0;
}

