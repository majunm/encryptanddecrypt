package lib.comm.encrypt.and.decrypt;

import java.text.SimpleDateFormat;
import java.util.Date;

import security.config.Rsa;
import security.util.AesEncryptionUtil;

/**
 * 作者：马俊
 * 时间：2018/3/19 上午11:55
 * 邮箱：747673016@qq.com
 */

public class Tst {
    public static void main(String[] args) {
        String x = "http://natural.storage.76iw.com/head/eebb47750489b67951ccc79e4ad081b2.jpg";
        System.out.println(x.substring(x.lastIndexOf("/head")));
        SimpleDateFormat time = new SimpleDateFormat("yyyy-MM-dd");
        String parse = time.format(Long.parseLong("1531140099")*1000);
        System.out.println(parse);
        System.out.println(Long.parseLong("1531140099"));

//        System.out.println("AES加密后="+AesEncryptionUtil.encrypt("123456")+
//                "\nAES解密后="+AesEncryptionUtil.decrypt(AesEncryptionUtil.encrypt("123456"))+
//                "RSA加密后="+ Rsa.encryptByPublic("123456")+
//                "\nRSA解密后="+Rsa.decryptByPublic(Rsa.encryptByPublic("123456"))
//        );
    }
}
