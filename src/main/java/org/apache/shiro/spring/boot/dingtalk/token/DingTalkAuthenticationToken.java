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
package org.apache.shiro.spring.boot.dingtalk.token;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;

import com.dingtalk.api.response.OapiUserGetResponse.Roles;

/**
 * DingTalk Authentication Token
 * 
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class DingTalkAuthenticationToken extends DefaultAuthenticationToken {

	/**
	 * 	应用的唯一标识key
	 */
	private String key;
	private String code;
    private String loginTmpCode;
    
    /**
	 * 员工ID
	 */
	protected String userid;
    /**
	 * 是否已经激活，true表示已激活，false表示未激活
	 */
	private boolean active;
	/**
	 * 员工头像url
	 */
	protected String avatar;
	/**
	 * 员工名字
	 */
	protected String name;
	/**
	 * 员工昵称
	 */
	protected String nick;
	/**
	 * 员工手机号码
	 */
	protected String mobile;
	/**
	 * 员工电子邮箱
	 */
	protected String email;
	/**
	 * 员工工号
	 */
	protected String jobnumber;
	/**
	 * 员工在当前开放应用内的唯一标识
	 */
	protected String openid;
	/**
	 * 员工在当前开发者企业账号范围内的唯一标识，系统生成，固定值，不会改变
	 */ 
	protected String unionid;
	/**
	 * 员工备注
	 */
	private String remark;
	/**
	 * 入职时间。Unix时间戳 （在OA后台通讯录中的员工基础信息中维护过入职时间才会返回)
	 */
	private Date hiredDate;
	/**
	 * 员工职位信息
	 */
	private String position;
	/**
	 * 员工的企业邮箱，如果员工已经开通了企业邮箱，接口会返回，否则不会返回
	 */
	private String orgEmail;
	/**
	 * 员工正式手机号码
	 */
	private String inviteMobile;
	/**
	 * 办公地点
	 */
	private String workPlace;
	/**
	 * 分机号（仅限企业内部开发调用）
	 */
	private String tel;
	/**
	 * 是否为企业的管理员，true表示是，false表示不是
	 */
	private boolean admin;
	/**
	 * 是否为企业的老板，true表示是，false表示不是
	 */
	private boolean boss;
	/**
	 * 是否号码隐藏，true表示隐藏，false表示不隐藏
	 */
	private boolean hide;
	/**
	 * 是否是高管
	 */
	private boolean senior;
	/**
	 * 国家地区码
	 */
	private String stateCode;
	/**
	 * 用户所在角色列表
	 */
	private List<Roles> roles;
	/**
	 * 员工所属部门id列表
	 */
	protected List<Long> depts;
	/**
	 * 扩展属性，可以设置多种属性（手机上最多显示10个扩展属性，具体显示哪些属性，请到OA管理后台->设置->通讯录信息设置和OA管理后台->设置->手机端显示信息设置）。
	 * 该字段的值支持链接类型填写，同时链接支持变量通配符自动替换，目前支持通配符有：userid，corpid。
	 * 示例： [工位地址](http://www.dingtalk.com?userid=#userid#&corpid=#corpid#) 
	 */
	protected Map<String, String> extattr;

	public DingTalkAuthenticationToken( String key, String code, String loginTmpCode, String host) {
		this.key = key;
		this.code = code;
		this.loginTmpCode = loginTmpCode;
		this.setHost(host);
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
	public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public String getAvatar() {
		return avatar;
	}

	public void setAvatar(String avatar) {
		this.avatar = avatar;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getNick() {
		return nick;
	}

	public void setNick(String nick) {
		this.nick = nick;
	}

	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getJobnumber() {
		return jobnumber;
	}

	public void setJobnumber(String jobnumber) {
		this.jobnumber = jobnumber;
	}

	public String getOpenid() {
		return openid;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public String getUnionid() {
		return unionid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	public String getRemark() {
		return remark;
	}

	public void setRemark(String remark) {
		this.remark = remark;
	}

	public Date getHiredDate() {
		return hiredDate;
	}

	public void setHiredDate(Date hiredDate) {
		this.hiredDate = hiredDate;
	}

	public String getPosition() {
		return position;
	}

	public void setPosition(String position) {
		this.position = position;
	}

	public String getOrgEmail() {
		return orgEmail;
	}

	public void setOrgEmail(String orgEmail) {
		this.orgEmail = orgEmail;
	}

	public String getInviteMobile() {
		return inviteMobile;
	}

	public void setInviteMobile(String inviteMobile) {
		this.inviteMobile = inviteMobile;
	}

	public String getWorkPlace() {
		return workPlace;
	}

	public void setWorkPlace(String workPlace) {
		this.workPlace = workPlace;
	}

	public String getTel() {
		return tel;
	}

	public void setTel(String tel) {
		this.tel = tel;
	}

	public boolean isAdmin() {
		return admin;
	}

	public void setAdmin(boolean admin) {
		this.admin = admin;
	}

	public boolean isBoss() {
		return boss;
	}

	public void setBoss(boolean boss) {
		this.boss = boss;
	}

	public boolean isHide() {
		return hide;
	}

	public void setHide(boolean hide) {
		this.hide = hide;
	}

	public boolean isSenior() {
		return senior;
	}

	public void setSenior(boolean senior) {
		this.senior = senior;
	}

	public String getStateCode() {
		return stateCode;
	}

	public void setStateCode(String stateCode) {
		this.stateCode = stateCode;
	}

	public List<Roles> getRoles() {
		return roles;
	}

	public void setRoles(List<Roles> roles) {
		this.roles = roles;
	}

	public List<Long> getDepts() {
		return depts;
	}

	public void setDepts(List<Long> depts) {
		this.depts = depts;
	}

	public Map<String, String> getExtattr() {
		return extattr;
	}

	public void setExtattr(Map<String, String> extattr) {
		this.extattr = extattr;
	}

}
