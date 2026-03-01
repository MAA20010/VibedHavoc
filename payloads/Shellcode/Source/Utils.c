#include <Utils.h>
#include <Macro.h>

SEC( text, B ) UINT_PTR HashString( LPVOID String, UINT_PTR Length )
{
    ULONG	Hash = 54383;
    PUCHAR	Ptr  = String;

    if ( ! String ) {
        return 0;
    }

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) {
                ++Ptr;
                continue;  // Skip null bytes entirely
            }
        }

        // Also skip if we loaded a null character
        if ( character == 0x00 ) {
            ++Ptr;
            continue;
        }

        UCHAR lower_mask = (character >= 0x61) & (character <= 0x7A);
        character = character - (lower_mask << 5);

        Hash = character + (Hash << 4) + character + (Hash << 13) - Hash;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}