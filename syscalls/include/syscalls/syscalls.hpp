#pragma once

class syscalls
{
public:
	syscalls( )
	{
		ntdll = get_module_base( L"ntdll.dll" );
	};

	~syscalls( ) = default;

	template <typename ...args>
	NTSTATUS create( const std::string_view &func_name, args... a )
	{
		if ( !ntdll )
			return -1;

		const auto index = get_syscall_index( func_name );

		if ( !index )
			return -1;

		std::uint8_t shellcode[ 11 ]
		{
			0x4C, 0x8B, 0xD1,				// mov r10, rcx
			0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, index
			0x0F, 0x05,						// syscall
			0xC3							// ret
		};

		const auto alloc = VirtualAlloc( nullptr, sizeof( shellcode ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		
		std::memcpy( &shellcode[ 4 ], &index, sizeof( int ) );
		std::memcpy( alloc, &shellcode, sizeof( shellcode ) );

		NTSTATUS( __stdcall * func )( args... );
		*( void ** ) &func = alloc;

		return func( a... );
	}
private:
	std::uint64_t ntdll {};

	std::uint64_t get_module_base( const std::wstring_view & );
	std::int32_t  get_syscall_index( const std::string_view & );
};