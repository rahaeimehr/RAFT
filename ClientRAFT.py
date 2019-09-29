#import RAFT
import os
import time
from cryptography.hazmat.backends import default_backend
import base64
from cryptography import fernet
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography import utils
from struct import pack,unpack, unpack_from

class ClientRAFT(object):
    _lifeTime = 10
    def __init__(self, parent_token=None, backend=None):
        if backend is None:
            backend = default_backend()
        self._backend = backend

        if parent_token is not None:
            self.SetParentToken(parent_token)

    def SetParentToken(self,parent_token):
        self._parentToken = base64.urlsafe_b64decode(parent_token)
        self._signKey = self._parentToken[-32:-16]
        self._encryptionKey = self._parentToken[-16:]
        self._id = self._parentToken[:-32]

    def SetCommand(self, command):
        self._command = command

 
    def Finalize(self, life_time = None):
        if life_time is not None:
            self._lifeTime = life_time

        self._NewToken = pack(">BH" + 
                              str(len(self._id))+"s",
                              0x91,
                              len(self._id),
                              self._id)
        self._command=pack(">Q8s"+str(len(self._command))+"s", int(time.time())+self._lifeTime,os.urandom(8),self._command) #bytearray(self._command,"utf8")
        self._NewToken+=self._command
        self.h = HMAC(self._signKey, hashes.SHA256(), self._backend)
        self.h.update(self._NewToken)
        self._NewToken += self.h.finalize()
        return base64.urlsafe_b64encode(self._NewToken)

    def GetKey(self, token):
        v, = unpack_from(">B",token,0)
        if v==0x91 :
            lenId, = unpack_from(">H",token,1)
            OriginalId, = unpack_from(">" + str(lenId)+"s", token,3)
            cmd = token[19+lenId:]
            print(cmd)
            keys, cmds = self.GetKey(OriginalId)
            cmds.append(cmd)
            sign_key = keys[:16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token)  
            hmac=h.finalize()
            return hmac, cmds
        else:
            sign_key = base64.urlsafe_b64decode(SourceKey)[-32:-16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token)            
            return h.finalize(),[]
        return ""
    def ValidateRAFT(self, token):
        token = base64.urlsafe_b64decode(token)
        v, = unpack_from(">B",token,0)
        if v==0x91 :
            lenId, = unpack_from(">H",token,1)
            OriginalId, =  unpack_from(">"+str(lenId)+"s",token,3)
            cmd = token[19+lenId:-32] 
            print(cmd)
            keys,cmds = self.GetKey(OriginalId)
            cmds.append(cmd)
            sign_key = keys[:16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token[:-32])  
            hmac=h.finalize()
            if hmac== token[-32:]:
                print("It is valid")
                return True,cmds
            else:
                raise Exception("Error: Not a RAFT token (MAC)")
        else:
            raise Exception("Error: Not a RAFT token (Format)")
        return ""


SourceKey = '3he7wwxKPSMIRZ25xlpBOapqOYpHqW9qL2y1FCFH9ec='
SourceTokenGenerator = fernet.Fernet(SourceKey)

SourceToken = SourceTokenGenerator.encrypt(b"Hello")
print(SourceToken)
t1= time.time()
m1 = ClientRAFT(SourceToken)
m1.SetCommand("image/v2/images")
rt1= m1.Finalize()
print(time.time()-t1)
t1= time.time()
print(m1.ValidateRAFT(rt1))
print("Time to validate one-level RAFT:", time.time()-t1)
print(rt1)

m2 = ClientRAFT(rt1)
m2.SetCommand("bah bah")
rt2= m2.Finalize()

c1 = ClientRAFT(rt2)
c1.SetCommand("Chah Chah")

rt= c1.Finalize()

t1= time.time()
print(c1.ValidateRAFT(rt))
print(time.time()-t1)

#print("Fernet: \n",base64.urlsafe_b64decode(SourceToken))

#c2 = ClientRAFT(rt)
#rc = c2.ValidateRAFT()
#print(rc)
#print(len(rc),len(SourceToken))
