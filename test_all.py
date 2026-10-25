"""Тест всех модулей DocumentFlow."""
import sys
import os
import tempfile
import atexit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import signature as sig
import database as db

# 1. Test signature module
print("=== Тест модуля электронной подписи ===")

key = sig.generate_key_pair()
print("  Генерация ключевой пары RSA-2048: OK")

priv_pem = sig.serialize_private_key(key, b"TestPassword123")
pub_pem = sig.serialize_public_key(key)
print(f"  Сериализация ключей: private={len(priv_pem)}B, public={len(pub_pem)}B")

cert = sig.generate_certificate(key, "TestUser")
cert_pem = sig.serialize_certificate(cert)
print(f"  Генерация сертификата X.509: {len(cert_pem)}B")

data = b"This is a test document content for signing."
signature = sig.sign_document(data, key)
print(f"  Подписание документа (RSA-PSS, SHA-256): signature={len(signature)}B")

pub_key = sig.load_public_key(pub_pem)
result = sig.verify_signature(data, signature, pub_key)
assert result is True, "Verification should be True for valid signature"
print(f"  Верификация (корректная подпись): {result}")

result_tampered = sig.verify_signature(data + b"X", signature, pub_key)
assert result_tampered is False, "Verification should be False for tampered data"
print(f"  Верификация (изменённый документ): {result_tampered}")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
legacy_signature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
assert sig.verify_signature(data, legacy_signature, pub_key) is True
print("  Верификация подписи первой версии (максимальная соль): True")

# Восстановление EM = s^e mod n и разбор EMSA-PSS (RFC 8017, п. 9.1.2)
import hashlib
numbers = pub_key.public_numbers()
em = pow(int.from_bytes(signature, "big"), numbers.e, numbers.n).to_bytes(256, "big")
masked_db, h = em[:-33], em[-33:-1]
mask, counter = b"", 0
while len(mask) < len(masked_db):
    mask += hashlib.sha256(h + counter.to_bytes(4, "big")).digest()
    counter += 1
db_block = bytes(a ^ b for a, b in zip(masked_db, mask))
db_block = bytes([db_block[0] & 0x7F]) + db_block[1:]
ps_length = db_block.index(1)
salt = db_block[ps_length + 1:]
h_check = hashlib.sha256(b"\0" * 8 + hashlib.sha256(data).digest() + salt).digest()
assert em[-1] == 0xBC and ps_length == 190 and len(salt) == 32 and h_check == h
print(f"  EMSA-PSS: PS={ps_length} байт, соль={len(salt)} байта (sLen = hLen), H' = H")

sig_b64 = sig.encode_signature_b64(signature)
sig_decoded = sig.decode_signature_b64(sig_b64)
assert sig_decoded == signature
print(f"  Base64 кодирование/декодирование: OK")

# 2. Test database module
print("\n=== Тест модуля базы данных ===")

# Use temp db
test_directory = tempfile.TemporaryDirectory()
atexit.register(test_directory.cleanup)
db.DB_PATH = os.path.join(test_directory.name, "test_db.db")

db.init_db()
print("  Инициализация БД: OK")

user_id = db.create_user("testuser", "hash123", priv_pem, pub_pem, cert_pem)
print(f"  Создание пользователя: id={user_id}")

user = db.get_user_by_username("testuser")
assert user is not None
assert user["username"] == "testuser"
print(f"  Поиск пользователя по имени: OK")

user2 = db.get_user_by_id(user_id)
assert user2 is not None
print(f"  Поиск пользователя по ID: OK")

# Create a test file
test_file = os.path.join(test_directory.name, "test.txt")
with open(test_file, "w") as f:
    f.write("Test document content")

checksum = db.compute_checksum(b"Test document content")
doc_id = db.insert_document("test.txt", test_file, user_id, checksum)
print(f"  Сохранение документа: id={doc_id}, checksum={checksum[:16]}...")

docs = db.get_all_documents(user_id)
assert len(docs) == 1
print(f"  Получение списка документов: count={len(docs)}")

doc = db.get_document_by_id(doc_id)
assert doc is not None
print(f"  Получение документа по ID: OK")

db.save_signature(doc_id, user_id, sig_b64)
print(f"  Сохранение подписи: OK")

sig_info = db.get_signature_for_document(doc_id)
assert sig_info is not None
assert sig_info["signer_name"] == "testuser"
print(f"  Получение подписи документа: signer={sig_info['signer_name']}")

# Cleanup
os.remove(db.DB_PATH)
os.remove(test_file)
print("\n=== ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО ===")
