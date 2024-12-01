@echo off
setlocal

REM �f�B���N�g���ݒ�
set "output_dir=keys"
if not exist "%output_dir%" mkdir "%output_dir%"

REM RSA���y�A�̐���
echo Generating RSA key pair...
openssl genpkey -algorithm RSA -out "%output_dir%\rsa_private.key" -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in "%output_dir%\rsa_private.key" -out "%output_dir%\rsa_public.key"
echo RSA key pair generated: rsa_private.key and rsa_public.key

REM ECDSA���y�A�̐���
echo Generating ECDSA key pair...
openssl ecparam -name prime256v1 -genkey -noout -out "%output_dir%\ecdsa_private.key"
openssl ec -in "%output_dir%\ecdsa_private.key" -pubout -out "%output_dir%\ecdsa_public.key"
echo ECDSA key pair generated: ecdsa_private.key and ecdsa_public.key

REM �������b�Z�[�W
echo All keys have been generated in the "%output_dir%" directory.
pause
