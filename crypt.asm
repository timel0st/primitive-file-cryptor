LOCALS @@ ; задание префикса для локальных переменных
.model	small	; один сегмент кода, данных и стека
.stack	100h		; отвести под стек 256 байт
.data			; начало сегмента данных
    ; константы
    maxExt = 4 ; максимальная длина расширения (с точкой)
    maxPath = 80 ; максимальная длина пути до исходного файла
    maxKey = 8 ; максимальная длина ключа
    BUFSIZE = 4096 ; размер буфера для чтения/записи в файл
    ; переменные
    destHandle dw ? ; хэндл результирующего файла
    srcHandle dw ? ; хэндл исходного файла
    extOffset dw 0 ; Отступ от начала PSP до точки в пути в command tail (если нет, то остается нулём)
    extlen dw 0 ; длина расширения
    ext db maxExt DUP (?) ; расширение
    keylen dw 0 ; длина ключа
    curPos dw $+2 ; Номер текущего символа в ключе при шифровании/дешифровании
    key db maxKey DUP (?) ; ключ
    checkPhrase db 'abcdefgh' ; Последовательность символов для проверки правильности введённого ключа
    pathlen dw 0 ; длина пути
    path db maxPath+1 DUP (?) ; путь
    buf db BUFSIZE DUP (?) ; буфер для чтения/записи в файл
    enc db '.cry' ; расширение зашифрованного файла
.code

; Установка ds на сегмент данных
setDataSeg MACRO
    mov ax, @data
    mov ds, ax
ENDM

; Установка es на сегмент данных
setExtraSeg MACRO
    mov ax, @data
    mov es, ax
ENDM

; Макрос для выделения памяти под сообщение и его вывода
printMsg MACRO msg
    LOCAL str
.data
    str db msg, 0Dh, 0Ah, '$'
.code
    setDataSeg
    mov ah, 9
    mov dx, offset str
    int 21h
ENDM

;Выход из программы с заданным сообщением и кодом
exitWithMsg MACRO msg, code
    printMsg msg
    mov ah, 4Ch
    mov al, code
    int 21h
ENDM

;Шаблон для сравнения символа в аккумуляторе с символами окончания строки
;Отличается для разных случаев, определение по макс. длине
symbolChecks MACRO n
    IF n EQ maxPath
        cmp al, '.'
        jnz @@S
        mov [es:extOffset], si
    @@S:
    ENDIF
    IF (n EQ maxExt) OR (n EQ maxPath)
        cmp al, ' '
        jz @@E
    ENDIF
    cmp al, 0Dh
    jz @@E
ENDM

;Выдача ошибки при считывании
parseError MACRO n
    IF n EQ maxPath
        exitWithMsg 'Error: max path length was exceeded', 1
    ELSEIF n EQ maxExt
        exitWithMsg 'Error: max extension length was exceeded', 2
    ELSE
        exitWithMsg 'Error: max key length was exceeded', 3
    ENDIF
ENDM

;Шаблон для считывания символов
parseM MACRO n
    mov cx, n
    inc cx
@@L:
    lodsb
    symbolChecks n ; проверка текущего символа
    stosb
    loop @@L
    parseError n ; случай выхода за установленную границу длины аргумента
@@E:
    dec si
    ret
ENDM

;Шаблон для вызова функции считывания и подсчет и сохранение длины
parseAndGetLen MACRO name
    call _parse&name
    mov ax, max&name + 1
    sub ax, cx
    mov [es:&name&len], ax
ENDM

; Макросы + процедуры для работы с файлами, названия говорят сами за себя
createFile MACRO p, h
    push ds
    push offset h
    push offset p
    call _createFile
    add sp, 4
    pop ds
ENDM

_createFile proc
    arg p:word, h:word
    push bp
    mov bp, sp
    mov ah, 3Ch
    mov cx, 0
    mov dx, offset p
    int 21h
    jnc @@OK
    exitWithMsg 'Error: file create error', 4
@@OK:
    mov bx, offset h
    mov [bx], ax
    pop bp
    ret
_createFile endp

openFile MACRO p, h
    push ds
    push offset h
    push offset p
    call _openFile
    add sp, 4
    pop ds
ENDM

_openFile proc
    arg p:word, h:word
    push bp
    mov bp, sp
    mov ah, 3Dh
    mov al, 2 ; read and write
    mov dx, offset p
    int 21h
    jnc @@OK
    exitWithMsg 'Error: file open error', 5
@@OK:
    mov bx, offset h
    mov [bx], ax
    pop bp
    ret
_openFile endp


closeFile MACRO h
    push ds
    push offset h
    call _closeFile
    add sp, 2
    pop ds
ENDM

_closeFile proc
    arg h:word
    push bp
    mov bp, sp
    mov ah, 3Eh
    mov bx, offset h
    mov bx, [bx]
    int 21h
    jnc @@OK
    exitWithMsg 'Error: file close error', 6
@@OK:
    pop bp
    ret
_closeFile endp

readFile MACRO h, n, dest
    push ds
    push offset h
    mov ax, n
    push ax
    push offset dest
    call _readFile
    add sp, 6
    pop ds
ENDM

_readFile proc
    arg dest:word, n:word, h:word
    push bp
    mov bp, sp
    mov ah, 3Fh
    mov bx, offset h
    mov bx, [bx]
    mov cx, n
    mov dx, offset dest
    int 21h
    jnc @@OK
    exitWithMsg 'Error: read file error', 7
@@OK:
    pop bp
    ret
_readFile endp

writeFile MACRO h, n, src
    push ds
    push offset h
    mov ax, n
    push ax
    push offset src
    call _writeFile
    add sp, 6
    pop ds
ENDM

_writeFile proc
    arg src:word, n:word, h:word
    push bp
    mov bp, sp
    mov ah, 40h
    mov bx, offset h
    mov bx, [bx]
    mov cx, n
    mov dx, offset src
    int 21h
    jnc @@OK
    exitWithMsg 'Error: write file error', 8
@@OK:
    pop bp
    ret
_writeFile endp

; Макрос и процедура шифрования текста по заданному отступу и длине
encryptText MACRO a, l
    push ds
    mov ax, l
    push ax
    push offset a
    call _encryptText
    add sp, 4
    pop ds
ENDM

_encryptText proc
    arg a:word, l:word
    push bp
    mov bp, sp
    mov cx, l
    mov si, [curpos] ; текущая позиция курсора на ключе, т.е. отступ по которому будет взят символ ключа
    lea dx, [key]  
    add dx, [keylen]
    mov di, offset a
@@L:
    lodsb
    add al, [di] ; сложение ключа с символом шифруемой строки
    stosb
    cmp si, dx ; проверка длины ключа
    jnz @@S
    mov si, offset key ; В случае выхода за границу ключа - берем этот ключ сначала
@@S:
    loop @@L
    mov [curpos], si ; сохранение текущей позиции курсора на ключе
    pop bp
    ret
_encryptText endp

; Макрос и процедура дешифрования текста по заданному отступу и длине
; Во многом аналогичен функции шифрования
; Производит вычитание ключа из зашифрованных байтов
decryptText MACRO a, l
    push ds
    mov ax, l
    push ax
    push offset a
    call _decryptText
    add sp, 4
    pop ds
ENDM

_decryptText proc
    arg a:word, l:word
    push bp
    mov bp, sp
    mov cx, l
    mov si, [curpos]
    lea dx, [key]
    add dx, [keylen]
    mov di, offset a
@@L:
    mov ah, [di] ; Символ дешифруемой строки
    lodsb
    sub ah, al ; Вычитание ключа из символа дешифруемой строки
    mov al, ah
    stosb ; Запись дешифрованного символа
    cmp si, dx
    jnz @@S
    mov si, offset key
@@S:
    loop @@L
    mov [curpos], si
    pop bp
    ret
_decryptText endp

;макрос+процедура сравнения строк по отступам s и d длины n, 0 в ax если строки равны, иначе 1 в ax
strncmp MACRO s, d, n
    push ds
    push offset s
    push offset d
    mov ax, n
    push ax
    call _strncmp
    add sp, 6
    pop ds
ENDM

_strncmp proc
    arg n: word, d: word, s: word 
    push bp
    mov bp, sp
    mov cx, n
    mov si, offset s
    mov di, offset d
@@L:
    lodsb
    scasb
    jnz @@N
    loop @@L
    mov ax, 0
    pop bp
    ret
@@N:
    mov ax, 1
    pop bp
    ret
_strncmp endp

; Процедура для пропуска ведущих пробелов по отступу в ds:si, меняет si
_skipLeadingSpaces proc
@@L:
    lodsb
    cmp al, ' '
    jz @@L
    dec si ; возвращаем позицию источника на первый не пробел
    ret
_skipLeadingSpaces endp

; Процедура считывания аргументов командной строки
;сначала парсится полный путь
;если есть расширение - возврат к нему и запись в отдельный участок памяти
_parseArgs proc
    setExtraSeg
    mov si, 81h ; начало строки с аргументами командной строки
    parseAndGetLen Path
    mov dx, [es:extOffset]
    test dx, dx
    jz @@S
    mov si, dx
    dec si
    parseAndGetLen Ext
@@S:
    parseAndGetLen Key
_parseArgs endp

; Считывание пути в память
_parsePath proc
    mov di, offset path
    call _skipLeadingSpaces
    parseM maxPath
_parsePath endp

; Считывание расширения (может отсутствовать)
_parseExt proc
    mov di, offset ext
    parseM maxExt
_parseExt endp

; Считывание ключа
_parseKey proc
    mov di, offset key
    call _skipLeadingSpaces
    parseM maxKey
_parseKey endp

; Проверка расширения входного файла
_checkExt proc
    strncmp ext, enc, maxExt
    test ax, ax
    jnz @@E
    ;Если расширение .cry - дешифруем
    call _decrypt
    ret 
@@E:
    ;Если расширение отличное от .cry - шифруем
    call _encrypt
    ret
_checkExt endp

; Макрос и процедура для изменения исходного пути для создания результирующего файла
swapExtEnc MACRO a
    push ds
    push offset a
    call _swapExtEnc
    add sp, 2
    pop ds
ENDM

_swapExtEnc proc
    arg a: word
    push bp
    mov bp, sp
    mov ax, [extlen]
    mov dx, offset path
    add dx, [pathlen]
    sub dx, ax
    mov si, offset a
    mov di, dx
    xor cx, cx
    mov cx, maxExt
@@L:
    movsb
    loop @@L
    pop bp
    ret
_swapExtEnc endp

;Процедура для проверки длины считанного пути и ключа
_validate proc
    mov ax, [pathlen]
    test ax, ax
    jz @@E
    mov ax, [keylen]
    test ax, ax 
    jz @@E2
    ret
@@E:
    printMsg 'Missing path'
@@E2:
    printMsg 'Missing key'
    exitWithMsg 'USAGE: crypt [path] [key]', 0
_validate endp

; процедура шифрования входного файла
_encrypt proc
    ;Открытие исходного файла
    openFile path, srcHandle
    ;Замена расширения на .cry в пути файла
    swapExtEnc enc
    ;Создание результирующего файла
    createFile path, destHandle
    ;Шифрование проверочной фразы
    encryptText checkPhrase, maxKey
    ;Запись зашифрованной проверочной фразы
    writeFile destHandle, maxKey, checkPhrase
    ;Шифрование исходного расширения
    encryptText ext, maxExt
    ; Запись зашифрованного расширения
    writeFile destHandle, maxExt, ext
    ; Запись зашифрованного содержимого блоками размером BUFSIZE
@@L:
    ; считывание блока из исходного файла в буффер
    readFile srcHandle, bufsize, buf 
    ; Сохранение числа считанных байт на стеке
    push ax 
    ; Шифрование байтов в буфере
    encryptText buf, ax 
    ; Восстановление на AX числа считаных байтов
    pop ax 
    ; Запись зашифрованных байтов из результирующего буфера в файл
    writeFile destHandle, ax, buf 
    ; Если число прочитанных байт не равно размеру буфера - значит прочитали файл до конца, 
    cmp ax, bufsize
    ; Цикл пока файл не прочитан полностью
    jz @@L
    ;Закрытие обоих файлов
    closeFile destHandle
    closeFile srcHandle
    printMsg 'Encrypted'
    ret
_encrypt endp

; процедура дешифрования исходного файла
_decrypt proc
; Открытие исходного файла
    openFile path, srcHandle
; Чтение из файла зашифрованной проверочной фразы
    readFile srcHandle, maxKey, buf
; Дешифрование считанной фразы
    decryptText buf, maxKey
; Сравнение дешифрованной фразы с исходной
    strncmp buf, checkPhrase, maxKey
    test ax, ax
    jz @@OK
; Если ключ оказался неверным, выходим с сообщением
    exitWithMsg 'Wrong key', 0
@@OK:
;Чтение и дешифрование исходного расширения
    readFile srcHandle, maxExt, ext
    decryptText ext, maxExt
;Создание результирующего файла с исходным расширением
    swapExtEnc ext
    createFile path, destHandle
;Запись дешифрованного содержимого
;Аналогично процедуре _encrypt
@@L:
    readFile srcHandle, bufsize, buf
    push ax
    decryptText buf, ax
    pop ax
    writeFile destHandle, ax, buf
    cmp ax, bufsize
    jz @@L
    ;Закрытие обоих файлов
    closeFile destHandle
    closeFile srcHandle
    printMsg 'Decrypted'
    ret
_decrypt endp

; Точка входа
start:
    call _parseArgs ; считывание аргументов командой строки
    setDataSeg ; Установка ds на сегмент данных
    call _validate ; Проверка наличия пути и ключа в командной строке
    call _checkExt ; Проверка расширения файла
    ;В теле _checkExt на основании считанного расширение просиходит вызов процедуры шифрования или дешифрования исходного файла
    exitWithMsg 'Success', 0 ; Успешное завершение программы
end start