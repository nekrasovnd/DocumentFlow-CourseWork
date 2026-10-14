import os,sys,tempfile,io,re,json
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root))
with tempfile.TemporaryDirectory() as tmp:
 out=Path(tmp)
 os.environ.update(DOCUMENTFLOW_DB=tmp+'/db.sqlite',DOCUMENTFLOW_UPLOADS=tmp+'/uploads',DOCUMENTFLOW_SECRET='test-only-secret-for-isolated-check-123456')
 import app,database as db,signature as sig
 app.app.config['TESTING']=True
 c=app.app.test_client(); results=[]
 def check(name,cond):
  assert cond,name
  results.append(name);print('OK',name)
 def token(client):
  with client.session_transaction() as s:return s['csrf_token']
 def post(client,path,data):return client.post(path,data={**data,'csrf_token':token(client)},follow_redirects=True)
 r=c.get('/register');(out/'register.html').write_text(r.text)
 r=post(c,'/register',{'username':'student','password':'Coursework2026!'})
 check('Регистрация и генерация ключей',r.status_code==200 and db.get_user_by_username('student') is not None)
 r=post(c,'/upload',{'document':(io.BytesIO(b'DocumentFlow coursework test.\n'),'example.txt')})
 check('Загрузка документа',r.status_code==200 and len(db.get_all_documents(1))==1)
 (out/'documents.html').write_text(r.text)
 check('Отклонение формы без CSRF-токена',c.post('/sign/1',data={'password':'Coursework2026!'}).status_code==400)
 check('Отклонение неверного пароля',post(c,'/sign/1',{'password':'WrongPass!'}).status_code==403)
 r=post(c,'/sign/1',{'password':'Coursework2026!'})
 check('Подписание документа',r.status_code==200 and db.get_signature_for_document(1) is not None)
 r=c.get('/verify/1');check('Проверка корректной подписи','Подпись криптографически корректна' in r.text)
 (out/'verify.html').write_text(r.text)
 check('Защита закрытого ключа',b'ENCRYPTED PRIVATE KEY' in db.get_user_by_id(1)['private_key_pem'])
 doc=db.get_document_by_id(1);Path(tmp+'/uploads',doc['filepath']).write_bytes(b'changed')
 r=c.get('/verify/1');check('Обнаружение изменения документа','Проверка подписи не пройдена' in r.text)
 (out/'tampered.html').write_text(r.text)
 c2=app.app.test_client();c2.get('/register');post(c2,'/register',{'username':'other','password':'Coursework2026!'})
 check('Запрет доступа другого пользователя',all(c2.get('/'+p+'/1').status_code==403 for p in ('verify','download')))
 check('Запрет подписания чужого документа',post(c2,'/sign/1',{'password':'Coursework2026!'}).status_code==403)
 check('Отклонение запрещённого расширения',post(c,'/upload',{'document':(io.BytesIO(b'x'),'file.exe')}).status_code==200 and len(db.get_all_documents(1))==1)
 check('Отклонение отсутствующего документа',c.get('/verify/999').status_code==404)
 (out/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
