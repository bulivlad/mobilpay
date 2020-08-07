package ro.mobilPay.util;


import lombok.extern.slf4j.Slf4j;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

@Slf4j
public class FileHelper {
	
	public static String getFileContents(String filePath) {
		
		try(FileInputStream file = new FileInputStream (filePath)) {
			DataInputStream in = new DataInputStream (file);
			byte[] b = new byte[in.available()];
			in.readFully (b);
			in.close ();
			return new String(b);
		} catch (IOException e) {
			log.error("Error occured at reading file " + filePath, e);
		} 

		return null;
		          
		
	}

}
