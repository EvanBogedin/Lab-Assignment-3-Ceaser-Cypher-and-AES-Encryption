# Evan
# Get user input
plain_test_message = input("\nPlease enter a plain text message: ")
shift_value = input("\nPlease enter shift value: ")

# encrypting
encrypted_message = ""
for c in list(plain_test_message):
    encrypted_message += chr( int(ord(c)) + int(shift_value) )

# decrypting
decrypted_message = ""
for c in list(encrypted_message):
    encrypted_message += chr( int(ord(c)) - int(shift_value) )

# prints
print("\n\nEncrypted: ", encrypted_message)
print("\nDecrypted:", decrypted_message)