/*
 * Copyright 2024 OpenARC contributors.
 * See LICENSE.
 */

#include "build-config.h"

#include <assert.h>
#include <string.h>

#include "arc-nametable.h"

/**
 *  Translate a code to its name.
 *
 *  Parameters:
 *      table: name table
 *      code: code to translate
 *
 *  Returns:
 *      Pointer to the name matching the provided code, or NULL if not found.
 */
const char *
arc_code_to_name(struct nametable *table, int code)
{
    assert(table != NULL);

    while (table->nt_name != NULL)
    {
        if (table->nt_code == code)
        {
            return table->nt_name;
        }
        table++;
    }

    return NULL;
}

/**
 *  Translate a name to its code.
 *
 *  Parameters:
 *      table: name table
 *      name: name to translate
 *
 *  Returns:
 *      A code matching the provided name, or the default defined in
 *      the table if not found.
 */
int
arc_name_to_code(struct nametable *table, const char *name)
{
    assert(table != NULL);

    while (table->nt_name != NULL)
    {
        if (strcasecmp(table->nt_name, name) == 0)
        {
            return table->nt_code;
        }
        table++;
    }

    return table->nt_code;
}
