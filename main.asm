.686
.model flat,stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib




.data?
    fileHandle dd ?
    fileBuffer db 512 dup(?)
    readCount dd ?

    fileHandle_file_enc dd ?
    fileBuffer_file_enc db 512 dup(?)
    writeCount dd ?

    fileHandle_file_dec dd ?
    fileBuffer_file_dec db 512 dup(?)
    readCount_file_dec dd ?




.data
    ;variavel string que fala quais opções o usuario tem para selecionar, no caso são 3 opções uma pra encryptar o programa uma pra decryptar e uma pra sair
    menu db "1 - Encryptar",0dh,0ah,"2 - Decryptar",0dh,0ah,"3 - Sair",0dh,0ah,"4 - CryptoAnalise",0dh,0ah,"Escolha uma opcao: ",0
    string_arquivo_encryptar db "Digite o nome do arquivo para ser encryptado: ",0
    string_arquivo_gerar db "Digite o nome do arquivo que vai ser gerado: ",0
    chave_encryptar db "Digite a chave: ",0

    string_arquivo_decryptar db "Digite o nome do arquivo para ser decryptado: ",0
    string_arquivo_gerar_decryptado db "Digite o nome do arquivo que vai ser gerado: ",0
    chave_decryptar db "Digite a chave: ",0

    string_arquivo_cryptoanalise db "Digite o nome do arquivo para a cryptoanalise: ",0

    erro_arquivo db "Erro ao abrir o arquivo",0


    inputString db 50 dup(0)
    inputGenerate db 50 dup(0)
    outputString db 50 dup(0)
    inputHandle dd 0 ; Variavel para armazenar o handle de entrada
    outputHandle dd 0 ; Variavel para armazenar o handle de saida
    console_count dd 0 ; Variavel para armazenar caracteres lidos/escritos na console
    tamanho_string dd 0 ; Variavel para armazenar tamanho de string terminada em 0
    opcao dd 0 ; Variavel para armazenar a opcao escolhida pelo usuario

    chave_enc dd 0

    mensagem_fim_processo db 0ah,"fim do processo",0ah, 0
    mensagem_encryptando db 0ah,"Encryptando",0ah, 0
    mensagem_encryptado db 0ah,"Encryptado",0ah, 0
    mensagem_decryptando db 0ah,"Decryptando",0ah, 0
    mensagem_decryptado db 0ah,"Decryptado",0ah, 0


.code

func_encrypt:
    push ebp
    mov ebp, esp

    mov eax, [ebp+8] ; endereço da string
    mov ebx, [ebp+12] ; chave
    mov ecx, [ebp+16] ; tamanho da string
    xor esi, esi
    xor edi, edi

    mov esi, eax
    encrypt_loop:
        mov al, [esi + edi] ; move o conteudo atual no caso o caracter (byte) para o registrador al
        add al, bl; adiciona a chave de cryptografia ao byte 
        mov [esi + edi], al; move o byte criptografado para o endereço de memoria
        inc edi ; incrementa o contador de caracteres para passar para o próximo caractere.
        cmp edi, ecx ; Compara o contador de caracteres com o tamanho da string.
        jl encrypt_loop; Salta para "encrypt" se esi for menor que ecx (ainda há caracteres a serem processados).
        add esi, 1; incrementa o contador de caracteres para passar para o próximo caractere.

    mov esp, ebp
    pop ebp
    ret 12

func_decrypt:
    push ebp
    mov ebp, esp

    mov eax, [ebp+8] ; endereço da string
    mov ebx, [ebp+12] ; chave
    mov ecx, [ebp+16] ; tamanho da string
    xor esi, esi
    xor edi, edi

    mov esi, eax
    decrypt_loop:
        mov al, [esi + edi]; move o conteudo atual no caso o caracter (byte) para o registrador al
        sub al, bl; subtrai a chave de cryptografia ao byte
        mov [esi + edi], al; move o byte criptografado para o endereço de memoria
        inc edi; incrementa o contador de caracteres para passar para o próximo caractere.
        cmp edi, ecx ; Compara o contador de caracteres com o tamanho da string.
        jl decrypt_loop ; Salta para "decrypt" se esi for menor que ecx (ainda há caracteres a serem processados).
        add esi, 1; incrementa o contador de caracteres para passar para o próximo caractere.

    mov esp, ebp
    pop ebp
    ret 12




start:

    console:
    invoke GetStdHandle, STD_INPUT_HANDLE ; Pega o handle de entrada
    mov inputHandle, eax
    invoke GetStdHandle, STD_OUTPUT_HANDLE ; Pega o handle de saida
    mov outputHandle, eax

    invoke WriteConsole, outputHandle, addr menu, sizeof menu, addr console_count, NULL ; Escreve o menu na tela
    
    invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL ; Le a opcao escolhida pelo usuario

    mov esi, offset inputString ; inicio do tratamento para verificar se o usuario digitou um numero
    proximo:
        mov al, [esi]
        inc esi
        cmp al, 13 ; verifica se o caracter é o CR (carriage return)
        jne proximo
        dec esi
        xor al, al; se foi o CR ele vai colocar um 0 no lugar e parar a execução
        mov [esi], al

    invoke atodw, addr inputString ; transforma a string em um numero
    mov opcao, eax

    cmp opcao, 1
    je encryptar
    cmp opcao, 2
    je decryptar
    cmp opcao, 4
    je cryptoanalise
    cmp opcao, 3
    je sair
    jmp console

    encryptar: ; parte do codigo que vai encryptar
        ; solicita ao usuario o nome do arquivo que vai ser encryptado
        invoke WriteConsole, outputHandle, addr string_arquivo_encryptar, sizeof string_arquivo_encryptar, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL

        ; parte do codigo que vai tratar a string para remover o CR
        mov esi, offset inputString
        proximo_enc:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_enc
        dec esi
        xor al, al
        mov [esi], al

        ; abre o arquivo que vai ser encryptado, se não conseguir ele vai para o label erro.
        invoke CreateFile, addr inputString, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        mov fileHandle, eax; salva o handle do arquivo na variavel fileHandle
        cmp eax, INVALID_HANDLE_VALUE
        je erro

        ; solicita ao usuario o nome do arquivo que vai ser gerado com o arquivo encryptado
        invoke WriteConsole, outputHandle, addr string_arquivo_gerar, sizeof string_arquivo_gerar, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputGenerate, sizeof inputGenerate, addr console_count, NULL

        ; parte do codigo que vai tratar a string para remover o CR
        mov esi, offset inputGenerate
        proximo_generate_enc:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_generate_enc
        dec esi
        xor al, al
        mov [esi], al
        
        ; cria o arquivo que vai ser gerado com o arquivo encryptado, se não conseguir ele vai para o label erro.
        invoke CreateFile, addr inputGenerate, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
        mov fileHandle_file_enc, eax
        cmp eax, INVALID_HANDLE_VALUE
        je erro
        ; invoke WriteFile, fileHandle_file_enc, addr fileBuffer, readCount, addr writeCount, NULL


        ; solicita ao usuario a chave de encryptação
        invoke WriteConsole, outputHandle, addr chave_encryptar, sizeof chave_encryptar, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL

        ; trata o CR da string e prepara para transformar em um numero
        mov esi, offset inputString
        proximo_chave_enc:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_chave_enc
        dec esi
        xor al, al
        mov [esi], al
        
        invoke atodw, addr inputString
        mov chave_enc, eax


        ; joga a mensagem na tela falando que esta encryptando
        invoke WriteConsole, outputHandle, addr mensagem_encryptando, sizeof mensagem_encryptando, addr console_count, NULL

        ; loop que vai encryptar o arquivo completo passando de 512 em 512 bytes (maximo, no caso podendo pegar menos no final do arquivo em casos) do arquivo
        ; e escrevendo no arquivo que vai ser gerado
        loop_encrypt:

            invoke ReadFile, fileHandle, addr fileBuffer, 512, addr readCount, NULL

            push readCount
            push chave_enc
            push offset fileBuffer
            call func_encrypt

            invoke WriteFile, fileHandle_file_enc, addr fileBuffer, readCount, addr writeCount, NULL

            cmp readCount, 0
            jne loop_encrypt
            invoke WriteConsole , outputHandle, addr mensagem_fim_processo, sizeof mensagem_fim_processo, addr console_count, NULL
        

        ; fechamento dos arquivos
        invoke CloseHandle, fileHandle
        invoke CloseHandle, fileHandle_file_enc


        jmp console

        erro:
            invoke WriteConsole, outputHandle, addr erro_arquivo, sizeof erro_arquivo, addr console_count, NULL
            jmp console

    ; parte do codigo que vai decryptar, o codigo é praticamente o mesmo do encryptar, só muda a parte de chamar a função de decryptar
    decryptar:
        ; solicita ao usuario o nome do arquivo que vai ser decryptado
        invoke WriteConsole, outputHandle, addr string_arquivo_decryptar, sizeof string_arquivo_decryptar, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL

        ; parte do codigo que vai tratar a string para remover o CR
        mov esi, offset inputString
        proximo_dec:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_dec
        dec esi
        xor al, al
        mov [esi], al

        ; abre o arquivo que vai ser decryptado, se não conseguir ele vai para o label erro.
        invoke CreateFile, addr inputString, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        mov fileHandle, eax
        cmp eax, INVALID_HANDLE_VALUE
        je erro

        ; solicita ao usuario o nome do arquivo que vai ser gerado com o arquivo decryptado
        invoke WriteConsole, outputHandle, addr string_arquivo_gerar_decryptado, sizeof string_arquivo_gerar_decryptado, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputGenerate, sizeof inputGenerate, addr console_count, NULL

        mov esi, offset inputGenerate
        proximo_generate_dec:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_generate_dec
        dec esi
        xor al, al
        mov [esi], al
        
        ; cria o arquivo que vai ser gerado com o arquivo decryptado, se não conseguir ele vai para o label erro.
        invoke CreateFile, addr inputGenerate, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
        mov fileHandle_file_dec, eax
        cmp eax, INVALID_HANDLE_VALUE
        je erro
        ; invoke WriteFile, fileHandle_file_enc, addr fileBuffer, readCount, addr writeCount, NULL

        ; solicita ao usuario a chave de decryptação
        invoke WriteConsole, outputHandle, addr chave_decryptar, sizeof chave_decryptar, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL
        mov esi, offset inputString
        proximo_chave_dec:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_chave_dec
        dec esi
        xor al, al
        mov [esi], al
        
        invoke atodw, addr inputString
        mov chave_enc, eax

        ; joga a mensagem na tela falando que esta decryptando
        invoke WriteConsole, outputHandle, addr mensagem_decryptando, sizeof mensagem_decryptando, addr console_count, NULL
        loop_decrypt:
            
                invoke ReadFile, fileHandle, addr fileBuffer, 512, addr readCount, NULL

                push readCount
                push chave_enc
                push offset fileBuffer
                call func_decrypt
    
                invoke WriteFile, fileHandle_file_dec, addr fileBuffer, readCount, addr writeCount, NULL
    
                cmp readCount, 0
                jne loop_decrypt
                invoke WriteConsole , outputHandle, addr mensagem_fim_processo, sizeof mensagem_fim_processo, addr console_count, NULL
        
        ; fechamento dos arquivos
        invoke CloseHandle, fileHandle
        invoke CloseHandle, fileHandle_file_dec
        jmp console
    cryptoanalise:
        ; solicita ao usuario o nome do arquivo que vai ser decryptado
        invoke WriteConsole, outputHandle, addr string_arquivo_cryptoanalise, sizeof string_arquivo_cryptoanalise, addr console_count, NULL
        invoke ReadConsole, inputHandle, addr inputString, sizeof inputString, addr console_count, NULL

        ; parte do codigo que vai tratar a string para remover o CR
        mov esi, offset inputString
        proximo_cryptoanalise:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo_cryptoanalise
        dec esi
        xor al, al
        mov [esi], al

        ; abre o arquivo que vai ser decryptado, se não conseguir ele vai para o label erro.
        invoke CreateFile, addr inputString, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        mov fileHandle, eax
        cmp eax, INVALID_HANDLE_VALUE
        je erro

    sair:
        invoke ExitProcess, 0
end start
