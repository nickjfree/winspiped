#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include "unistd.h"

#include "warnp.h"

#include "entropy.h"

#include "windows.h"
#include "Wincrypt.h"

/**
 * XXX Portability
 * XXX We obtain random bytes from the operating system by opening
 * XXX /dev/urandom and reading them from that device; this works on
 * XXX modern UNIX-like operating systems but not on systems like
 * XXX win32 where there is no concept of /dev/urandom.
 */

/**
 * entropy_read(buf, buflen):
 * Fill the given buffer with random bytes provided by the operating system.
 */


/**
	Ignore all the bullshit above, we are doing it the Windows way.
*/


int entropy_read(uint8_t * buf, size_t buflen)
{
	HCRYPTPROV hCryptProv = NULL;      
	LPCSTR UserName = "winspiped";

	if (CryptAcquireContext(
		&hCryptProv,               // handle to the CSP
		UserName,                  // container name 
		NULL,                      // use the default provider
		PROV_RSA_FULL,             // provider type
		0)) {                        // flag values 
	} else 	{
		//-------------------------------------------------------------------
		// An error occurred in acquiring the context. This could mean
		// that the key container requested does not exist. In this case,
		// the function can be called again to attempt to create a new key 
		// container. Error codes are defined in Winerror.h.
		if (GetLastError() == NTE_BAD_KEYSET) {
			if (CryptAcquireContext(
				&hCryptProv,
				UserName,
				NULL,
				PROV_RSA_FULL,
				CRYPT_NEWKEYSET)) {
				printf("A new key container has been created.\n");
			} else {
				printf("Could not create a new key container.\n");
				exit(1);
			}
		} else {
			printf("A cryptographic service handle could not be "
				"acquired.\n");
			exit(1);
		}
	}
	if (!CryptGenRandom(hCryptProv, buflen, buf)) {
		printf("error read entropy %d\n", __LINE__);
	}
	return 0;
}
