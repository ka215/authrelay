@echo off
setlocal

REM 出力先ディレクトリ設定
set "output_dir=keys"
if not exist "%output_dir%" mkdir "%output_dir%"

REM RSA鍵ペアの生成
echo Generating RSA key pair...
openssl genpkey -algorithm RSA -out "%output_dir%\rsa_private.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -in "%output_dir%\rsa_private.pem" -pubout -out "%output_dir%\rsa_public.pem"
echo RSA key pair generated: rsa_private.pem and rsa_public.pem

REM ECDSA鍵ペアの生成
echo Generating ECDSA key pair...
openssl ecparam -name prime256v1 -genkey -noout -out "%output_dir%\ecdsa_private.pem"
openssl ec -in "%output_dir%\ecdsa_private.pem" -pubout -out "%output_dir%\ecdsa_public.pem"
echo ECDSA key pair generated: ecdsa_private.pem and ecdsa_public.pem

REM 完了メッセージ
echo All keys have been generated in the "%output_dir%" directory as .pem files.
pause
