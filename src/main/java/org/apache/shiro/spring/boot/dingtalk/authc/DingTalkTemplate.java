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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.DefaultDingTalkClient;
import com.dingtalk.api.DingTalkClient;
import com.dingtalk.api.request.OapiGettokenRequest;
import com.dingtalk.api.request.OapiSnsGettokenRequest;
import com.dingtalk.api.request.OapiSnsGetuserinfoBycodeRequest;
import com.dingtalk.api.request.OapiUserGetRequest;
import com.dingtalk.api.request.OapiUserGetUseridByUnionidRequest;
import com.dingtalk.api.request.OapiUserGetuserinfoRequest;
import com.dingtalk.api.response.OapiGettokenResponse;
import com.dingtalk.api.response.OapiSnsGettokenResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.dingtalk.api.response.OapiUserGetuserinfoResponse;
import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.taobao.api.ApiException;

/**
 * https://open-doc.dingtalk.com/microapp/serverapi2/eev437
 * https://blog.csdn.net/yangguosb/article/details/79762565
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public class DingTalkTemplate {

	private final String DINGTALK_SERVICE = "https://oapi.dingtalk.com";
	private final String METHOD_GET = "GET";

	private final LoadingCache<String, Optional<String>> ACCESS_TOKEN_CACHES = CacheBuilder.newBuilder()
			// 设置并发级别为8，并发级别是指可以同时写缓存的线程数
			.concurrencyLevel(8)
			// 正常情况下access_token有效期为7200秒，有效期内重复获取返回相同结果，并自动续期
			.expireAfterWrite(6000, TimeUnit.SECONDS)
			// 设置缓存容器的初始容量为10
			.initialCapacity(2)
			// 设置缓存最大容量为100，超过100之后就会按照LRU最近虽少使用算法来移除缓存项
			.maximumSize(10)
			// 设置要统计缓存的命中率
			.recordStats()
			// 设置缓存的移除通知
			.removalListener(new RemovalListener<String, Optional<String>>() {
				@Override
				public void onRemoval(RemovalNotification<String, Optional<String>> notification) {
					System.out.println(notification.getKey() + " was removed, cause is " + notification.getCause());
				}
			})
			// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
			.build(new CacheLoader<String, Optional<String>>() {

				@Override
				public Optional<String> load(String keySecret) throws Exception {

					OapiGettokenRequest request = new OapiGettokenRequest();

					JSONObject key = JSONObject.parseObject(keySecret);
					//request.setCorpid(key.getString("corpId"));
					//request.setCorpsecret(key.getString("corpSecret"));
					request.setAppkey(key.getString("appKey"));
					request.setAppsecret(key.getString("appSecret"));
					
					request.setHttpMethod(METHOD_GET);
					
					DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/gettoken");
					OapiGettokenResponse response = client.execute(request);

					if (response.isSuccess()) {
						String token = response.getAccessToken();
						return Optional.fromNullable(token);
					}
					return Optional.fromNullable(null);
				}
			});

	private final LoadingCache<String, Optional<String>> SNS_ACCESS_TOKEN_CACHES = CacheBuilder.newBuilder()
			// 设置并发级别为8，并发级别是指可以同时写缓存的线程数
			.concurrencyLevel(8)
			// 设置写缓存后600秒钟过期
			.expireAfterWrite(6000, TimeUnit.SECONDS)
			// 设置缓存容器的初始容量为10
			.initialCapacity(2)
			// 设置缓存最大容量为100，超过100之后就会按照LRU最近虽少使用算法来移除缓存项
			.maximumSize(10)
			// 设置要统计缓存的命中率
			.recordStats()
			// 设置缓存的移除通知
			.removalListener(new RemovalListener<String, Optional<String>>() {
				@Override
				public void onRemoval(RemovalNotification<String, Optional<String>> notification) {
					System.out.println(notification.getKey() + " was removed, cause is " + notification.getCause());
				}
			})
			// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
			.build(new CacheLoader<String, Optional<String>>() {

				@Override
				public Optional<String> load(String keySecret) throws Exception {

					OapiSnsGettokenRequest request = new OapiSnsGettokenRequest();

					JSONObject key = JSONObject.parseObject(keySecret);

					request.setAppid(key.getString("appId"));
					request.setAppsecret(key.getString("appSecret"));
					request.setHttpMethod(METHOD_GET);

					DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/sns/gettoken");

					OapiSnsGettokenResponse response = client.execute(request);

					if (response.isSuccess()) {
						String token = response.getAccessToken();
						return Optional.fromNullable(token);
					}
					return Optional.fromNullable(null);

				}
			});

	/**
	 * 企业内部开发获取access_token 先从缓存查，再到钉钉查
	 * https://open-doc.dingtalk.com/microapp/serverapi2/eev437
	 * @param appKey    企业Id
	 * @param appSecret 企业应用的凭证密钥
	 * @return the AccessToken
	 * @throws ApiException if get AccessToken Exception
	 */
	public String getAccessToken(String appKey, String appSecret) throws ApiException {
		try {
			
			JSONObject key = new JSONObject();
			key.put("appKey", appKey);
			key.put("appSecret", appSecret);

			Optional<String> opt = ACCESS_TOKEN_CACHES.get(key.toJSONString());
			return opt.isPresent() ? opt.get() : null;
			
		} catch (ExecutionException e) {
			throw new ApiException(e);
		}
	}
	
	/**
	 * 获取钉钉开放应用的ACCESS_TOKEN
	 * 
	 * @param appId    企业Id
	 * @param appSecret 企业应用的凭证密钥
	 * @return the AccessToken
	 * @throws ApiException if get AccessToken Exception
	 */
	public String getOpenToken(String appId, String appSecret) throws ApiException {
		try {
			
			JSONObject key = new JSONObject();
			key.put("appId", appId);
			key.put("appSecret", appSecret);
	
			Optional<String> opt = SNS_ACCESS_TOKEN_CACHES.get(key.toJSONString());
			return opt.isPresent() ? opt.get() : null;
		} catch (ExecutionException e) {
			throw new ApiException(e);
		}
	}
	
	/**
	 * 企业内部应用免登录：通过免登授权码和access_token获取用户信息
	 * https://ding-doc.dingtalk.com/doc#/serverapi2/clotub
	 * 
	 * @param code    		免登授权码，参考上述“获取免登授权码”
	 * @param accessToken 	调用接口凭证
	 * @return the OapiUserGetuserinfoResponse
	 * @throws ApiException if Api request Exception
	 */
	public OapiUserGetuserinfoResponse getUserinfoBycode( String code, String accessToken) throws ApiException {
		DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/user/getuserinfo");
		OapiUserGetuserinfoRequest request = new OapiUserGetuserinfoRequest();
		request.setCode(code);
		request.setHttpMethod(METHOD_GET);
		return client.execute(request, accessToken);
	}
	
	/**
	 * 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次。
	 * https://open-doc.dingtalk.com/microapp/serverapi2/kymkv6
	 * @param tmp_auth_code 用户授权的临时授权码code，只能使用一次；在前面步骤中跳转到redirect_uri时会追加code参数
	 * @param accessKey 	应用的appId
	 * @param accessSecret 	应用的secret
	 * @return the OapiUserGetuserinfoResponse
	 * @throws ApiException if Api request Exception 
	 */
	public OapiSnsGetuserinfoBycodeResponse getSnsGetuserinfoBycode( String tmp_auth_code, String accessKey, String accessSecret) throws ApiException {
		DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/sns/getuserinfo_bycode");
		OapiSnsGetuserinfoBycodeRequest request = new OapiSnsGetuserinfoBycodeRequest();
		request.setTmpAuthCode(tmp_auth_code);
		return client.execute(request, accessKey, accessSecret);
	}
	
	/**
	 * 根据unionid获取userid
	 * https://open-doc.dingtalk.com/microapp/serverapi2/ege851#-5
	 * 
	 * @param unionid 员工在当前企业内的唯一标识，也称staffId。可由企业在创建时指定，并代表一定含义比如工号，创建后不可修改，企业内必须唯一。长度为1~64个字符，如果不传，服务器将自动生成一个userid。
	 * @param accessToken 	调用接口凭证
	 * @return the OapiUserGetUseridByUnionidResponse
	 * @throws ApiException if Api request Exception 
	 */
	public OapiUserGetUseridByUnionidResponse getUseridByUnionid( String unionid, String accessToken) throws ApiException {
		
		DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/user/getUseridByUnionid");
		OapiUserGetUseridByUnionidRequest request = new OapiUserGetUseridByUnionidRequest();
		request.setUnionid(unionid);
		request.setHttpMethod(METHOD_GET);
		
		return client.execute(request, accessToken);
	}

	/*
	 * 根据钉钉的userid拿取用户的详细信息(包括手机号，部门id，等)
	 * https://open-doc.dingtalk.com/microapp/serverapi2/ege851
	 * @param userid 用户ID
	 * @param accessToken 	调用接口凭证
	 * @return the OapiUserGetResponse
	 * @throws ApiException if Api request Exception 
	 */
	public OapiUserGetResponse getUserByUserid( String userid, String accessToken) throws ApiException {
		
		DingTalkClient client = new DefaultDingTalkClient(DINGTALK_SERVICE + "/user/get");
		OapiUserGetRequest request = new OapiUserGetRequest();
		request.setUserid(userid);
		request.setHttpMethod(METHOD_GET);
		
		return client.execute(request, accessToken);
	}

}
