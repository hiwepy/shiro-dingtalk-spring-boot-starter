package org.apache.shiro.spring.boot.dingtalk.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class DingTalkCodeIncorrectException extends AuthenticationException {

	public DingTalkCodeIncorrectException(String msg) {
		super(msg);
	}
	
	public DingTalkCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
	
}
