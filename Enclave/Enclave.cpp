/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tprotected_fs.h>

#define PRINTF_BUFSIZE          256
#define BUF_SIZE                4096

int printf(const char* fmt, ...) {
    char buf[PRINTF_BUFSIZE] = {0};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, PRINTF_BUFSIZE, fmt, args);
    va_end(args);
    ocall_print(buf);
    return 0;
}

int open(const char* path) {
    int fd = 0;
    ocall_open(&fd, path);
    return fd;
}

int create(const char* path) {
    int fd = 0;
    ocall_create(&fd, path);
    return fd;
}

ssize_t read(int fd, void* buf, size_t size) {
    ssize_t ret = 0;
    ocall_read(&ret, fd, buf, size);
    return ret;
}

ssize_t write(int fd, const void* buf, size_t size) {
    ssize_t ret = 0;
    ocall_write(&ret, fd, buf, size);
    return ret;
}

int close(int fd) {
    int ret = 0;
    ocall_close(&ret, fd);
    return ret;
}


int ecall_encrypt_file(const char* _input_file,
                        const char* _output_file,
                        const sgx_key_128bit_t* _key_128bit)
{
    sgx_key_128bit_t key_128bit;
    if (!sgx_is_outside_enclave(_key_128bit, sizeof(sgx_key_128bit_t)))
        return -1;
    memcpy(&key_128bit, _key_128bit, sizeof(sgx_key_128bit_t));

    int input_file = open(_input_file);
    if (input_file < 0) return -1;

    SGX_FILE* output_file = sgx_fopen(_output_file, "w", &key_128bit);
    if (output_file == NULL) {
        close(input_file);
        return -1;
    }

    ssize_t len;
    char buf[BUF_SIZE];
    while ((len = read(input_file, buf, BUF_SIZE)) > 0) {
        sgx_fwrite(buf, 1, len, output_file);
    }

    close(input_file);
    sgx_fclose(output_file);
    return 0;
}

int ecall_decrypt_file(const char* _input_file,
                        const char* _output_file,
                        const sgx_key_128bit_t* _key_128bit)
{
    sgx_key_128bit_t key_128bit;
    if (!sgx_is_outside_enclave(_key_128bit, sizeof(sgx_key_128bit_t)))
        return -1;
    memcpy(&key_128bit, _key_128bit, sizeof(sgx_key_128bit_t));

    SGX_FILE* input_file = sgx_fopen(_input_file, "r", &key_128bit);
    if (input_file == NULL) return -1;

    int output_file = create(_output_file);
    if (output_file < 0) {
        sgx_fclose(input_file);
        return -1;
    }

    ssize_t len;
    char buf[BUF_SIZE];
    while ((len = sgx_fread(buf, 1, BUF_SIZE, input_file)) > 0) {
        write(output_file, buf, len);
    }

    close(output_file);
    sgx_fclose(input_file);
    return 0;
}
