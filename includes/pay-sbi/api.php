<?php
/*
SBI Payment Gateway Helper 

*/
namespace aw2;

class SBI_Pay {
	//static $iv ='';
	//const METHOD = 'AES-128-CBC';
	const METHOD = 'aes-256-gcm';
	//static $prod_url = 'https://www.onlinesbi.com/merchant/merchantprelogin.htm';
	//static $prod_url = 'https://www.onlinesbi.com/merchant/merchantprelogin.htm';
//	static $prod_url = 'https://merchant.onlinesbi.sbi/merchant/merchantprelogin.htm';
//	static $uat_url = 'https://uatmerchant.onlinesbi.sbi/merchantgst/merchantprelogin.htm';

	static $prod_url = 'https://merchant.sbi.bank.in/merchant/merchantprelogin.htm';
	static $uat_url = 'https://merchant.sbiuat.bank.in/merchant/merchantprelogin.htm';

	//static $uat_url_new = 'https://uatmerchant.onlinesbi.sbi/merchant/merchantprelogin.htm';
	  //static $uat_url_new = 'https://uatmerchant.onlinesbi.sbi/merchant/merchantprelogin.htm';
	 // static $uat_url_new = 'https://uatmerchant.onlinesbi.sbi/merchant/merchantprelogin.htm';
	//  static $uat_verify_url_new = 'https://uatmerchant.onlinesbi.sbi/merchant/doubleverification.htm';
	 static $uat_url_new = 'https://merchant.sbiuat.bank.in/merchant/merchantprelogin.htm';
	  static $uat_verify_url_new = 'https://merchant.sbiuat.bank.in/thirdparties/doubleverification.htm';

	//static $prod_verify_url = 'https://www.onlinesbi.com/thirdparties/doubleverification.htm';
	//static $prod_verify_url = 'https://merchant.onlinesbi.sbi/thirdparties/doubleverification.htm';
	static $prod_verify_url = 'https://merchant.sbi.bank.in/thirdparties/doubleverification.htm';	
	//static $uat_verify_url = 'https://uatmerchant.onlinesbi.com/thirdparties/doubleverification.htm';
	//static $uat_verify_url = 'https://uatmerchant.onlinesbi.sbi/thirdparties/doubleverification.htm';
	static $uat_verify_url = 'https://merchant.sbiuat.bank.in/thirdparties/doubleverification.htm';
		
	
	public static function make_string($args){
			$str=array();
			foreach($args as $key=>$value){
				$str[] = $key.'='.$value;
			}
			$str = implode('|',$str);
			$str = $str.'|checkSum='.hash('sha256', $str); 
			return $str;
		}

	public static function sbi_encrypt($message, $key,$iv){
		$tag='';
        if (mb_strlen($key, '8bit') !== 32) {
            throw new \Exception("Needs a 256-bit key! " .mb_strlen($key, '8bit'));
        }

        $ciphertext = openssl_encrypt($message,self::METHOD,$key, OPENSSL_RAW_DATA,$iv, $tag);

        $finalEncryption= base64_encode($iv . $ciphertext.$tag);
        return $finalEncryption;
    }
	
	public static function sbi_decrypt($ciphertext, $key,$iv){
		$tag='';
        if (mb_strlen($key, '8bit') !== 32) {
            throw new \Exception("Needs a 256-bit key!");
        }
		
		
		
		$c = base64_decode($ciphertext);
		
		$datalength=strlen($c);
		$ivlen = openssl_cipher_iv_length(self::METHOD);
		
		$ciphertext_raw = substr($c,16,$datalength-32);
		$tag=substr($c,$datalength-16,16);
		$original_plaintext = openssl_decrypt($ciphertext_raw, self::METHOD, $key, $options=OPENSSL_RAW_DATA, $iv, $tag);  
		
		return $original_plaintext;
	  
    }
	
	public static function process_payment($dev_mode='on', $encdata='',$merchant_code='', $submit_form = true){
		if(empty($encdata)){
			\aw2_library::set_error('encdata is empty'); 
			return;
		}
		
		if(empty($merchant_code)){
			\aw2_library::set_error('merchant code is empty'); 
			return;
		}
			
		$url=self::$prod_url;
		if(strtolower($dev_mode)=='on')
			$url=self::$uat_url_new;

		$form ='
		<form name="paymentform" id="paymentform" method="POST" action="'.$url.'">
			<input type="hidden" name="encdata" value="'.$encdata.'"/>
			<input type="hidden" name="merchant_code" value="'.$merchant_code.'"/>
		</form>
		<script>	
		 '.(!$submit_form ? '// comment ' : '').'document.paymentform.submit();
		</script>
		';
		
		return $form;
	}
	public static function re_verify_payment($dev_mode='on', $data='',$merchant_code='',$key, $iv){
		
		if(empty($data)){
			\aw2_library::set_error('data is empty'); 
			return;
		}
		
		if(empty($merchant_code)){
			\aw2_library::set_error('merchant code is empty'); 
			return;
		}
		
		
			
		$url=self::$prod_verify_url;
		if($dev_mode=='on')
			$url=self::$uat_verify_url;
		
		//$url='https://uatmerchant.onlinesbi.com/thirdparties/doubleverification.htm';
		
		$verification_string ="ref_no=".$data['ref_no']."|amount=".$data['amount'] ;
		//$verification_string .="|checkSum=".md5($verification_string);
		$verification_string .="|checkSum=".hash('sha256', $verification_string);
			
		$rencdata=SBI_Pay::sbi_encrypt($verification_string, $key,$iv);
		$v_data= array(
			"body"=>array(
					"encdata"=>$rencdata,
					"merchant_code" =>$merchant_code
				)
		);
		//send to server
		// [aw2.get function.wp_remote_post p1='https://uatmerchant.onlinesbi.com/thirdparties/doubleverification.htm ' p2="{dbv}" set='sbiresponse'/]
		
		$sbiresponse = wp_remote_post($url,$v_data);
				
		$v_dec_data=self::sbi_decrypt($sbiresponse['body'],$key,$iv);
		
		$v_dec_data=explode('|',$v_dec_data);
	
		$checksum=array_pop($v_dec_data);
		$checksum=explode('=',$checksum);
	
		$v_dec_data = implode('|',$v_dec_data);
		
		//$tmp_checksum=md5($v_dec_data);
		$tmp_checksum=hash('sha256', $v_dec_data);
		
		$vpairs=array();	
			
		if($tmp_checksum == trim($checksum[1])){
			
			$temp = explode ('|',$v_dec_data);
			foreach ($temp as $pair) 
			{
				list ($k,$v) = explode ('=',$pair);
				$vpairs[$k] = $v;
			}
		}
		else{
			\aw2_library::set_error('re verification checksum failed'); 
			return ;
		}
		
		
		return $vpairs;
	}
	public static function verify_payment($dev_mode='on', $encdata='',$merchant_code='',$key, $iv){
		
		if(empty($encdata)){
			\aw2_library::set_error('encdata is empty'); 
			return;
		}
		
		if(empty($merchant_code)){
			\aw2_library::set_error('merchant code is empty'); 
			return;
		}
		
		$dec_data=self::sbi_decrypt($encdata,$key,$iv);
		$dec_data=explode('|',$dec_data);
		
		$checksum=array_pop($dec_data);
		$checksum=explode('=',$checksum);
		
		$dec_data = implode('|',$dec_data);
		
	
		$tmp_checksum=hash('sha256', $dec_data);

		if(trim($tmp_checksum) == trim($checksum[1])){
			$temp = explode ('|',$dec_data);
			foreach ($temp as $pair) 
			{
				list ($k,$v) = explode ('=',$pair);
				$pairs[$k] = $v;
			}
		}
		else{
			\aw2_library::set_error('checksum failed'); 
			return ;
		}
			
		$url=self::$prod_verify_url;
		if(strtolower($dev_mode)=='on')
			$url=self::$uat_verify_url;
		
		//$url='https://uatmerchant.onlinesbi.com/thirdparties/doubleverification.htm';
		
		$verification_string ="ref_no=".$pairs['ref_no']."|amount=".$pairs['amount'] ;
		$verification_string .="|checkSum=".hash('sha256', $verification_string);
		
		$rencdata=SBI_Pay::sbi_encrypt($verification_string, $key,$iv);
		$v_data= array(
			"body"=>array(
					"encdata"=>$rencdata,
					"merchant_code" =>$merchant_code
				)
		);
		//send to server
		// [aw2.get function.wp_remote_post p1='https://uatmerchant.onlinesbi.com/thirdparties/doubleverification.htm ' p2="{dbv}" set='sbiresponse'/]
		
		$sbiresponse = wp_remote_post($url,$v_data);
			
		$v_dec_data=self::sbi_decrypt($sbiresponse['body'],$key,$iv);
		
		$v_dec_data=explode('|',$v_dec_data);
		
		$checksum=array_pop($v_dec_data);
		$checksum=explode('=',$checksum);
		
		$v_dec_data = implode('|',$v_dec_data);
		
		$tmp_checksum=hash('sha256', $v_dec_data);

		$vpairs=array();
		

		if(trim($tmp_checksum) == trim($checksum[1])){
			
			$temp = explode ('|',$v_dec_data);
			foreach ($temp as $pair) 
			{
				list ($k,$v) = explode ('=',$pair);
				$vpairs[$k] = $v;
			}
		}
		else{
			\aw2_library::set_error('verification checksum failed'); 
			return ;
		}
		
		
		return array_merge($pairs,$vpairs);
	}
	
}

/* 
function aw2_sbi_decrypt($encd){
	$key=(file_get_contents('/var/www/ilslaw.edu/ILSLAWCOLLEGE.key', true));
	$iv ='1234567890123467567';
	$dec_data=SBI_Pay::sbi_decrypt($encd,$key,$iv);
	
	$dec_data=explode('|',$dec_data);
	
	$checksum=array_pop($dec_data);
	$checksum=explode('=',$checksum);
	
	$dec_data = implode('|',$dec_data);
	
	$tmp_checksum=md5($dec_data);
	
	if($tmp_checksum == $checksum[1]){
		echo 'checksum passed';
		$temp = explode ('|',$dec_data);
		foreach ($temp as $pair) 
		{
			list ($k,$v) = explode ('=',$pair);
			$pairs[$k] = $v;
		}
		aw2_library::set('sbi',$pairs);
	}
	else{
		echo "checksum failed.".$tmp_checksum." == ".$checksum[1];
	}
}

function aw2_sbi_dv_setup($data){
	$key=(file_get_contents('/var/www/ilslaw.edu/ILSLAWCOLLEGE.key', true));
	$iv ='1234567890123467567';
	
	//$dec_data=SBI_Pay::sbi_decrypt($encd,$key);
	$verification_string ="ref_no=".$data['ref_no']."|amount=".$data['amount'] ;
	$verification_string .="|checkSum=".md5($verification_string);
	
	$encdata=SBI_Pay::sbi_encrypt($verification_string, $key,$iv);
	aw2_library::set('sbi.encdata',$encdata);
	
} */
