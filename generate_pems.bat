@echo off
setlocal

REM �o�͐�f�B���N�g���ݒ�
set "output_dir=keys"
if not exist "%output_dir%" mkdir "%output_dir%"

REM RSA���y�A�̐���
echo Generating RSA key pair...
openssl genpkey -algorithm RSA -out "%output_dir%\rsa_private.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -in "%output_dir%\rsa_private.pem" -pubout -out "%output_dir%\rsa_public.pem"
echo RSA key pair generated: rsa_private.pem and rsa_public.pem

REM ECDSA���y�A�̐���
echo Generating ECDSA key pair...
openssl ecparam -name prime256v1 -genkey -noout -out "%output_dir%\ecdsa_private.pem"
openssl ec -in "%output_dir%\ecdsa_private.pem" -pubout -out "%output_dir%\ecdsa_public.pem"
echo ECDSA key pair generated: ecdsa_private.pem and ecdsa_public.pem

REM �������b�Z�[�W
echo All keys have been generated in the "%output_dir%" directory as .pem files.
pause
