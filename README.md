# syscalls
only x64 is supported.

## Usage

```cpp
#include "stdafx.hpp"
#include "syscalls/syscalls.hpp"

int main( )
{
	const auto syscalls_ = std::make_unique<syscalls>( );

	syscalls_->create( "NtTerminateProcess", ( HANDLE ) -1, ( NTSTATUS ) 1337 );
}
```
