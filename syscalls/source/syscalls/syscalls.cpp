#include "stdafx.hpp"
#include "syscalls/syscalls.hpp"
#include "syscalls/undocumented.hpp"	

std::uint64_t syscalls::get_module_base( const std::wstring_view &name )
{
	const auto peb = reinterpret_cast< PPEB64 >( __readgsqword( 0x60 ) );
	const auto ldr_data = reinterpret_cast< PPEB_LDR_DATA >( peb->Ldr );

	for ( auto list_entry = ldr_data->InLoadOrderModuleList.Flink; list_entry != &ldr_data->InLoadOrderModuleList; list_entry = list_entry->Flink )
	{
		const auto ldr_entry = CONTAINING_RECORD( list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
		
		if ( ldr_entry && name.compare( ldr_entry->BaseDllName.Buffer ) == 0 )
			return reinterpret_cast< std::uint64_t >( ldr_entry->DllBase );
	}

	return 0;
}

std::int32_t  syscalls::get_syscall_index( const std::string_view &name )
{
	const auto dos = reinterpret_cast< PIMAGE_DOS_HEADER >( ntdll );
	
	if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
		return -1;

	const auto nt = reinterpret_cast< PIMAGE_NT_HEADERS > ( ntdll + static_cast< std::uint64_t >( dos->e_lfanew ) );
	
	if ( nt->Signature != IMAGE_NT_SIGNATURE )
		return -1;

	const auto export_dir_va = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
	const auto export_dir = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( ntdll + export_dir_va );
	
	if ( !export_dir )
		return -1;

	const auto name_offset_array = reinterpret_cast< DWORD * >( ntdll + export_dir->AddressOfNames );
	const auto ordinal_array = reinterpret_cast< std::uint16_t * >( ntdll + export_dir->AddressOfNameOrdinals );
	const auto func_offset_array = reinterpret_cast< DWORD * >( ntdll + export_dir->AddressOfFunctions );

	for ( auto i = 0ull; i < export_dir->NumberOfNames; ++i )
	{
		if ( name.compare( reinterpret_cast< const char * >( ntdll + name_offset_array[ i ] ) ) == 0 )
			return *( std::int32_t * ) ( ntdll + func_offset_array[ ordinal_array[ i ] ] + 0x4 );
	}
}