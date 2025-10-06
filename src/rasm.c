/** Implements the assembler, outputting Lanide Extended 64 machine code. */

#include "argparser.h"
#include "definitions.h"
#include "diag.h"
#include "eitable.h"
#include <ctype.h>
#include <errno.h>

static FILE *fin = NULL;
static FILE *fout = NULL;
static uint8_t *text_buffer = NULL;
static uint8_t *rodata_buffer = NULL;
static uint8_t *data_buffer = NULL;

static char *trim(char *string)
{
    char *end = NULL;

    while (isspace((uint8_t)*string))
    {
        string++;
    }

    if (*string == '\0')
    {
        return string;
    }

    // Trim trailing space
    end = string + strlen(string) - 1;
    while (end > string && isspace((uint8_t)*end))
    {
        end--;
    }

    end[1] = '\0';

    return string;
}

// Checks if the given string is a numeric zero.
static bool is_zero(const char *string)
{
    if (!string || !*string)
    {
        return false;
    }

    char *endptr = NULL;
    u64_it value = strtoull(string, &endptr, 0);

    if (*endptr != '\0')
    {
        return false;
    }

    return value == 0;
}

// Returns the operand size based on the operand passed.
uint16_t get_operand_size(const char *operand)
{
    if (!operand || !*operand)
    {
        return 0;
    }

    uint32_t length = strlen(operand);
    char first_char = *operand;
    char last_char = operand[length - 1];

    // If it's an immediate, assume it's 64-bit.
    char *endptr = NULL;
    strtoull(operand, &endptr, 0);
    if (*endptr == '\0')
    {
        return 64;
    }
    
    // Infer operand size from register used.

    if (first_char == 'r' && (length == 2 || length == 3))
    {
        return 64;
    }
    if ((first_char == 'd' || last_char == 'd') && (length == 3 || length == 4))
    {
        return 32;
    }
    if (last_char == 'w' || (length == 2 && (first_char == 'x' || first_char == 'b' || first_char == 's')))
    {
        return 16;
    }
    if ((last_char == 'b' || last_char == 'l') && (length >= 2 && length <= 4))
    {
        return 8;
    }

    return 0;
}

// Function used for bsearch() comparison.
static int compare_instruction(const void *a, const void *b)
{
    return strcmp((const char *)a, ((const struct instruction_entry *)b)->mnemonic);
}

// Finds instruction on the instruction map with bsearch() help.
struct instruction_entry *find_instruction(const char *mnemonic)
{
    return bsearch(
        mnemonic,
        instruction_table,
        instruction_count,
        sizeof(struct instruction_entry),
        compare_instruction
    );
}

// Display help message.
static int display_help(void)
{
    puts("Usage: rasm [options] <file>");
    puts("Options:");
    puts("    --help              Display this help message");
    puts("    -v, --version       Display version information");
    puts("    -o <output>         Write the assembled machine code to <output>");
    return 0;
}

// Display version information.
static int display_version(void)
{
    puts("rasm version " RASM_VERSION);
    return 0;
}

// Cleanup before exit.
static void cleanup(void)
{
    if (fin)
    {
        fclose(fin);
    }
    if (fout)
    {
        fclose(fout);
    }
    free(text_buffer);
    free(rodata_buffer);
    free(data_buffer);
}

int main(int argc, char *argv[])
{
    char *input_file = NULL;
    char *output_file = NULL;
    struct option options[] = {
        { .name = "--help" },
        { .name = "--version" },
        { .name = "-v" }, // Alias of --version
        { .name = "-o", .value = &output_file, .takes_value = true },
    };

    set_progname(argv[0]);
    optional_enable_vt_mode();
    atexit(cleanup);

    // Parse arguments passed.
    // An argument not tied to an option is expected to be the input file.
    int position = parse_args(argc, argv, options, sizeof(options) / sizeof(options[0]));

    // --help
    if (options[0].present)
    {
        return display_help();
    }

    // -v, --version
    if (options[1].present || options[2].present)
    {
        return display_version();
    }

    if (apstat & APEN_NODEFAULT)
    {
        emit_fatal("missing input file");
    }

    if (position < 0)
    {
        return 1;
    }
    input_file = argv[position];

    // Validate their extensions.
    if (!ends_with(input_file, ".asm"))
    {
        emit_error("input file must have '.asm' extension");
    }
    if (!ends_with(output_file, ".lx"))
    {
        emit_error("output file must have '.lx' extension");
    }

    fin = fopen(input_file, "r");
    fout = fopen(output_file, "wb");
    if (!fin || !fout)
    {
        emit_fatal("failed to open file: %s", strerror(errno));
    }

    // Allocate space for the .text, .rodata, and .data sections
    text_buffer = calloc(MEM_SIZE / 2, 1);
    rodata_buffer = calloc(MEM_SIZE / 2, 1);
    data_buffer = calloc(MEM_SIZE / 2, 1);
    if (!text_buffer || !rodata_buffer || !data_buffer)
    {
        emit_fatal("failed to allocate memory: %s", strerror(errno));
    }
    size_t text_size = 0;
    size_t rodata_size = 0;
    size_t data_size = 0;

    // "ID" of the current section.
    uint16_t current_section = SECT_INVALID;

    char line[256] = {0};
    size_t line_number = 0;
    while (fgets(line, sizeof(line), fin))
    {
        line_number++;

        // Skip comments and newlines.
        if (*trim(line) == ';' || *trim(line) == '\n')
        {
            continue;
        }

        char mnemonic[32] = {0};
        char destination[32] = {0};
        char source[32] = {0};
        struct instruction ei = {0};

        // Parse the line
        int n = sscanf(line, "%31s %31[^,], %31s", mnemonic, destination, source);
        if (n <= 0)
        {
            continue;
        }

        // Emit a byte
        if (STR_EQUAL_LEN(mnemonic, ".byte", 5))
        {
            ei.length = 1;
            ei.bytes[0] = strtoul(destination, NULL, 0) & 0xff;
            goto write;
        }

        // Emit a word
        if (STR_EQUAL_LEN(mnemonic, ".word", 5))
        {
            unsigned long value = strtoul(destination, NULL, 0);
            ei.length = 2;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            goto write;
        }

        // Emit a dword
        if (STR_EQUAL_LEN(mnemonic, ".dword", 6))
        {
            unsigned long value = strtoul(destination, NULL, 0);
            ei.length = 4;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            ei.bytes[2] = (value >> 16) & 0xff;
            ei.bytes[3] = (value >> 24) & 0xff;
            goto write;
        }

        // Emit a qword
        if (STR_EQUAL_LEN(mnemonic, ".qword", 6))
        {
            u64_it value = strtoull(destination, NULL, 0);
            ei.length = 8;
            for (int i = 0; i < 8; i++)
            {
                ei.bytes[i] = (value >> i * 8) & 0xff;
            }
            goto write;
        }
        
        // Change the section
        if (STR_EQUAL_LEN(mnemonic, ".section", 8))
        {
            if (STR_EQUAL_LEN(destination, ".text", 5))
            {
                current_section = SECT_TEXT;
            }
            else if (STR_EQUAL_LEN(destination, ".rodata", 7))
            {
                current_section = SECT_RODATA;
            }
            else if (STR_EQUAL_LEN(destination, ".data", 5))
            {
                current_section = SECT_DATA;
            }
            else
            {
                emit_error("unrecognized section: '%s'", destination);
            }
            continue;
        }
        
        ei.operand_size = get_operand_size(destination) ? get_operand_size(destination) : get_operand_size(source);
        if (ei.operand_size == 0 && n > 1)
        {
            emit_warning("at %s:%zu: unable to infer operand size, assuming 64-bit", input_file, line_number);
            ei.operand_size = 64;
        }

        if (STR_EQUAL_LEN(mnemonic, "div", 3) && is_zero(source))
        {
            emit_warning("at %s:%zu: division by zero", input_file, line_number);
        }

        // Uh oh! Illegal instruction! These cannot be accessed as an operand.
        // We use the `ends_with()` function here even though it's currently intended for use with file names :P

        char *bad_symbol = NULL;
        if (ends_with(destination, "ip") || ends_with(destination, "flags"))
        {
            bad_symbol = destination;
        }
        else if (ends_with(source, "ip") || ends_with(source, "flags"))
        {
            bad_symbol = source;
        }

        if (bad_symbol)
        {
            emit_error("at %s:%zu: forbidden access to: %s", input_file, line_number, bad_symbol);
        }

        struct instruction_entry *ie = find_instruction(mnemonic);
        if (ie)
        {
            ie->encode(&ei, destination, source);
        }
        else
        {
            emit_error("at %s:%zu: unknown mnemonic: '%s'", input_file, line_number, mnemonic);
        }

write:

        // Write the buffers to their respective sections
        switch (current_section)
        {
            case SECT_TEXT:
                if (text_size + ei.length > MEM_SIZE / 2)
                {
                    emit_fatal("text section overflow");
                }
                memcpy(text_buffer + text_size, ei.bytes, ei.length);
                text_size += ei.length;
                break;
            case SECT_RODATA:
                if (rodata_size + ei.length > MEM_SIZE / 2)
                {
                    emit_fatal("rodata section overflow");
                }
                memcpy(rodata_buffer + rodata_size, ei.bytes, ei.length);
                rodata_size += ei.length;
                break;
            case SECT_DATA:
                if (data_size + ei.length > MEM_SIZE / 2)
                {
                    emit_fatal("data section overflow");
                }
                memcpy(data_buffer + data_size, ei.bytes, ei.length);
                data_size += ei.length;
                break;
            default:
                emit_error("unknown section: %u", current_section);
        }
    }

    if (errors_emitted != 0)
    {
        return 1;
    }

    // Write the magic bytes
    fwrite(magic_bytes, 1, MAGIC_BYTES_SIZE, fout);

    // Write the offset of .rodata
    uint32_t rodata_offset = TEXT_FILE_OFFSET + text_size;
    fwrite(&rodata_offset, sizeof(uint32_t), 1, fout);

    // Write the offset of .data
    uint32_t data_offset = TEXT_FILE_OFFSET + text_size + rodata_size;
    fwrite(&data_offset, sizeof(uint32_t), 1, fout);

    // Write the contents of .text
    fwrite(text_buffer, 1, text_size, fout);

    // Write the contents of .rodata
    fwrite(rodata_buffer, 1, rodata_size, fout);

    // Write the contents of .data
    fwrite(data_buffer, 1, data_size, fout);

    return 0;
}