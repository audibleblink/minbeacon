/*!
 *
 * MINBEACON
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( CryptImportPublicKeyInfo );
	D_API( CryptAcquireContextA );
	D_API( CryptReleaseContext );
	D_API( CryptDecodeObjectEx );
	D_API( RtlAllocateHeap );
	D_API( CryptDestroyKey );
	D_API( CryptEncrypt );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_CRYPTIMPORTPUBLICKEYINFO		0x28b94686 /* CryptImportPublicKeyInfo */
#define H_API_CRYPTACQUIRECONTEXTA		0xc4e81a47 /* CryptAcquireContextA */
#define H_API_CRYPTRELEASECONTEXT		0x674798fd /* CryptReleaseContext */
#define H_API_CRYPTDECODEOBJECTEX		0x35691aef /* CryptDecodeObjectEx */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_CRYPTDESTROYKEY			0x0ec7f6aa /* CryptDestroyKey */
#define H_API_CRYPTENCRYPT			0xae7f897c /* CryptEncrypt */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Encrypts a buffer using RSA-1024
 *
!*/
D_SEC( B ) BOOL CryptEncryptRsa( _In_ PMINBEACON_CTX Context, _In_ PVOID KeyBuffer, _In_ UINT32 KeyLength, _In_ PVOID InBuffer, _In_ UINT32 InLength, _In_ PVOID* OutBuffer, _In_ PUINT32 OutLength )
{
	API			Api;

	PCERT_PUBLIC_KEY_INFO	Inf = NULL;

	UINT32			Len = 0;
	HCRYPTKEY		Key = 0;
	HCRYPTPROV		Prv = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Build Stack API Table ( 1 ) */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	/* Build Stack API Table ( 2 ) */
	Api.CryptImportPublicKeyInfo = PeGetFuncEat( Context->C32, H_API_CRYPTIMPORTPUBLICKEYINFO );
	Api.CryptAcquireContextA     = PeGetFuncEat( Context->Adv, H_API_CRYPTACQUIRECONTEXTA );
	Api.CryptReleaseContext      = PeGetFuncEat( Context->Adv, H_API_CRYPTRELEASECONTEXT );
	Api.CryptDecodeObjectEx      = PeGetFuncEat( Context->C32, H_API_CRYPTDECODEOBJECTEX );
	Api.CryptDestroyKey          = PeGetFuncEat( Context->Adv, H_API_CRYPTDESTROYKEY );
	Api.CryptEncrypt             = PeGetFuncEat( Context->Adv, H_API_CRYPTENCRYPT );

	/* Acquire a context to the RSA provider */
	if ( Api.CryptAcquireContextA( &Prv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) ) {
		/* Decode the public key to get the size ( DER ) */
		if ( ! Api.CryptDecodeObjectEx( X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, KeyBuffer, KeyLength, 0, NULL, NULL, &Len ) ) {
			/* Allocate the CERT_PUBLIC_KEY_INFO */
			if ( ( Inf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len ) ) != NULL ) {
				/* Attempt to decode the public key ( DER ) */
				if ( Api.CryptDecodeObjectEx( X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, KeyBuffer, KeyLength, 0, Inf, Len, &Len ) ) {
					/* Import the cryptographic key */
					if ( Api.CryptImportPublicKeyInfo( Prv, X509_ASN_ENCODING, Inf, &Key ) ) {
						/* Free the key */
						Api.CryptDestroyKey( Key );
					};
				};
				/* Free the memory */
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Inf );
			};
		};

		/* Free the crypt provider */
		Api.CryptReleaseContext( Prv, 0 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
