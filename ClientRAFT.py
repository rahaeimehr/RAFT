import RAFT
import os
import time
from cryptography.hazmat.backends import default_backend
import base64
from cryptography import fernet
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography import utils
from struct import pack,unpack

class ClientRAFT(object):
    fernetKey = base64.urlsafe_b64decode('3he7wwxKPSMIRZ25xlpBOapqOYpHqW9qL2y1FCFH9ec=')
    def __init__(self, fernet_token=None, backend=None):
        if backend is None:
            backend = default_backend()
        self._backend = backend

        if fernet_token is not None:
            self.SetSourceToken(fernet_token)

    def SetSourceToken(self,fernet_token):
        self._OriginalToken = base64.urlsafe_b64decode(fernet_token)
        self._sign_key = self._OriginalToken[-32:-16]
        self._encryption_key = self._OriginalToken[-16:]
        self._id = self._OriginalToken[:-32]

    def SetCommand(self, command):
        self._command = command

    def Finalize(self):

        self._NewToken = pack(">BH" + 
                              str(len(self._id))+"s",
                              0x91,
                              len(self._id),
                              self._id)
        self._command=pack(">HQ8s"+str(len(self._command))+"s",len(self._command), int(time.time()),os.urandom(8),bytearray(self._command,"utf8"))
        self._NewToken+=self._command
        self.h = HMAC(self._sign_key, hashes.SHA256(), self._backend)
        self.h.update(self._NewToken)
        self._NewToken += self.h.finalize()
        return base64.urlsafe_b64encode(self._NewToken)

    def GetKey(self, token):

        if token[0]==0x91 :
            lenId, = unpack(">H",token[1:3])
            OriginalId =  token[3:3+lenId]
        #    cmd = token[3+lenId:-32] 
            keys = self.GetKey(OriginalId)
            sign_key = keys[:16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token)  
            hmac=h.finalize()
            return hmac
        else:
            sign_key = base64.urlsafe_b64decode(SourceKey)[-32:-16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token)            
            return h.finalize()
        return ""
    def ValidateRAFT(self, token):
        if token[0]==0x91 :
            lenId, = unpack(">H",token[1:3])
            OriginalId =  token[3:3+lenId]
        #    cmd = token[3+lenId:-32] 
            keys = self.GetKey(OriginalId)
            sign_key = keys[:16]
            h = HMAC(sign_key, hashes.SHA256(), self._backend)
            h.update(token[:-32])  
            hmac=h.finalize()
            if hmac== token[-32:]:
                print("It is valid")
                return hmac
            else:
                raise Exception("Error: Not a RAFT token (MAC)")
        else:
            raise Exception("Error: Not a RAFT token (Format)")
        return ""


    def ValidateTokenTest(self):
        if self._id[0]==0x91 :
            print("RAFT")
            self._lenId, = unpack(">H",self._id[1:3])
            print(self._id)
            self._OriginalId =  self._id[3:3+self._lenId]
            self._sign_key = base64.urlsafe_b64decode(SourceKey)[-32:-16]
            self.h2 = HMAC(self._sign_key, hashes.SHA256(), self._backend)
            self.h2.update(self._OriginalId)
            self._OriginalToken= base64.urlsafe_b64encode(self._OriginalId + self.h2.finalize())
            return self._OriginalToken

        else:
            print("error")

        return 1

SourceKey = '3he7wwxKPSMIRZ25xlpBOapqOYpHqW9qL2y1FCFH9ec='
SourceTokenGenerator = fernet.Fernet(SourceKey)

SourceToken = SourceTokenGenerator.encrypt(b"Hello")

m1 = ClientRAFT(SourceToken)
m1.SetCommand("bah bah")
rt1= m1.Finalize()

m2 = ClientRAFT(rt1)
m2.SetCommand("jooon")
rt2= m2.Finalize()

c1 = ClientRAFT(rt2)
c1.SetCommand("Chah Chah")

rt= c1.Finalize()
print(c1.ValidateRAFT(base64.urlsafe_b64decode(rt)))

#print("Fernet: \n",base64.urlsafe_b64decode(SourceToken))

#c2 = ClientRAFT(rt)
#rc = c2.ValidateRAFT()
#print(rc)
#print(len(rc),len(SourceToken))
