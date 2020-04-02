/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.dingtalk.authc;

import java.nio.charset.StandardCharsets;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.spring.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.apache.shiro.spring.boot.dingtalk.token.DingTalkAuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * 小程序微信认证 (authentication)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class DingTalkAuthenticatingFilter extends AbstractTrustableAuthenticatingFilter {

	private static final Logger LOG = LoggerFactory.getLogger(DingTalkAuthenticatingFilter.class);
	public static final String SPRING_SECURITY_FORM_APP_KEY = "key";
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";
    public static final String SPRING_SECURITY_FORM_TMPCODE_KEY = "loginTmpCode";

    private String keyParameter = SPRING_SECURITY_FORM_APP_KEY;
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private String tmpCodeParameter = SPRING_SECURITY_FORM_TMPCODE_KEY;
	
	public DingTalkAuthenticatingFilter() {
		super();
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		// 判断是否无状态
		if (isSessionStateless()) {
			// Step 1、生成 Shiro Token 
			AuthenticationToken token = createToken(request, response);
			try {
				//Step 2、委托给Realm进行登录  
				Subject subject = getSubject(request, response);
				subject.login(token);
				//Step 3、执行授权成功后的函数
				return onAccessSuccess(token, subject, request, response);
			} catch (AuthenticationException e) {
				//Step 4、执行授权失败后的函数
				return onAccessFailure(token, e, request, response);
			}
		}
		return super.isAccessAllowed(request, response, mappedValue);
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		
		// 1、判断是否登录请求 
		if (isLoginRequest(request, response)) {
			
			if (isLoginSubmission(request, response)) {
				if (LOG.isTraceEnabled()) {
					LOG.trace("Login submission detected.  Attempting to execute login.");
				}
				return executeLogin(request, response);
			} else {
				String mString = "Authentication url [" + getLoginUrl() + "] Not Http Post request.";
				if (LOG.isTraceEnabled()) {
					LOG.trace(mString);
				}
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_BAD_REQUEST);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
		}
		// 2、未授权情况
		else {
			
			String mString = "Attempting to access a path which requires authentication. ";
			if (LOG.isTraceEnabled()) { 
				LOG.trace(mString);
			}
			
			// Ajax 请求：响应json数据对象
			if (WebUtils.isAjaxRequest(request)) {
				
				WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
				
				// Response Authentication status information
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.fail(mString));
				
				return false;
			}
			// 普通请求：重定向到登录页
			saveRequestAndRedirectToLogin(request, response);
			return false;
		}
	}
	
	 
    
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Post && JSON");
			}
			
			try {
				DingTalkLoginRequest loginRequest = objectMapper.readValue(request.getReader(), DingTalkLoginRequest.class);
				
				if ( !StringUtils.hasText(loginRequest.getKey())) {
					LOG.debug("No key (appId or appKey) found in request.");
					throw new DingTalkCodeNotFoundException("No key (appId or appKey) found in request.");
				}
				if ( !StringUtils.hasText(loginRequest.getCode()) && !StringUtils.hasText(loginRequest.getLoginTmpCode())) {
					LOG.debug("No loginTmpCode or Code found in request.");
					throw new DingTalkCodeNotFoundException("No loginTmpCode or Code found in request.");
				}
				return new DingTalkAuthenticationToken(loginRequest.getKey(), loginRequest.getCode(), loginRequest.getLoginTmpCode(), getHost(request));
			} catch (Exception e) {
				throw new AuthenticationException(e);
			}
		}
		
		String key = obtainKey(request);
        String code = obtainCode(request);
        String tmpCode = obtainTmpCode(request);
        
        if (key == null) {
        	key = "";
        }
        if (code == null) {
        	code = "";
        }
        if (tmpCode == null) {
        	tmpCode = "";
        }
        
		return new DingTalkAuthenticationToken(key, code, tmpCode, getHost(request));
	}

	protected String obtainKey(ServletRequest request) {
        return request.getParameter(keyParameter);
    }
    
    protected String obtainCode(ServletRequest request) {
        return request.getParameter(codeParameter);
    }
    
    protected String obtainTmpCode(ServletRequest request) {
        return request.getParameter(tmpCodeParameter);
    }

	public String getKeyParameter() {
		return keyParameter;
	}

	public void setKeyParameter(String keyParameter) {
		this.keyParameter = keyParameter;
	}

	public String getCodeParameter() {
		return codeParameter;
	}

	public void setCodeParameter(String codeParameter) {
		this.codeParameter = codeParameter;
	}

	public String getTmpCodeParameter() {
		return tmpCodeParameter;
	}

	public void setTmpCodeParameter(String tmpCodeParameter) {
		this.tmpCodeParameter = tmpCodeParameter;
	}

}
