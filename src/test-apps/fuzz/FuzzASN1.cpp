/*
 *
 *    Copyright (c) 2013-2017 Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      This file implements a process to fuzz the certificate
 *      parser for weave.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include "FuzzUtils.h"
#include "../tools/weave/weave-tool.h"
#include <Weave/Support/ASN1.h>

using namespace nl::Weave::ASN1;

bool gOpenSSLSet = false;

static void traverseASN1(ASN1Reader& asn1Parser)
{
    ASN1_ERROR err = ASN1_NO_ERROR;

    int nestLevel = 0;
    while (true)
    {
        err = asn1Parser.Next();
        if (err != ASN1_NO_ERROR)
        {
            if (err == ASN1_END)
            {
                if (asn1Parser.IsContained())
                {
                    err = asn1Parser.ExitConstructedType();
                    if (err != ASN1_NO_ERROR)
                    {
                        return;
                    }
                    nestLevel--;
                    continue;
                }
                else
                    break;
            }
            return;
        }
        else if (asn1Parser.Class == 0)
        if (asn1Parser.IsConstructed)
        {
            err = asn1Parser.EnterConstructedType();
            if (err != ASN1_NO_ERROR)
            {
                return;
            }
            nestLevel++;
        }
    }

    return;
}
//Assume the user compiled with clang > 6.0
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ASN1Reader reader;
    reader.Init(data, size);
    traverseASN1(reader);
    /*
    while ( reader.Next() == ASN1_NO_ERROR ) {
    }
    */
    return 0;
}

// When NOT building for fuzzing using libFuzzer, supply a main() function to satisfy
// the linker.  Even though the resultant application does nothing, being able to link
// it confirms that the fuzzing tests can be built successfully.
#ifndef WEAVE_FUZZING_ENABLED
int main(int argc, char *argv[])
{
    return 0;
}
#endif
