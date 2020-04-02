package org.apache.shiro.spring.boot.dingtalk.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class DingTalkCodeExpiredException extends AuthenticationException {

	public DingTalkCodeExpiredException(String msg) {
		super(msg);
	}
	
	public DingTalkCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
