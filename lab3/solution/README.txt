#Chuanrui Li, 1000010846, chuanrui.li@mail.utoronto.ca
#Jing Wang, 1002093183, jimmmy.wang@mail.utoronto.ca

For the generateQRcode.c:
We convert Account_name, Issuer and Secret into correct format and then put them into URL to generate correct QRcode. For the Secret, we first convert the ASCII character into the hex format. Then by using the base32_encode() function, the program will convert hex into the base32 number. Finally, we combine all the date into the URL.


For the ValidateQRCode.c:
We follow the HMAC = H[(K ⊕ opad) || H((K ⊕ ipad) || M)] formula. First, we using the secret hex to create both inner(ipad) and outer keys(opad). Then we use the sha1 function to hashing the message with relevant key twice. The message for the HTOP and TOTP is different. Message for HTOP is the counter 1 and Message for TOTP is the current time.
