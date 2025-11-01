package com.bitget.openapi.dto.response;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.bean.copier.CopyOptions;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.*;

/**
 * ResponseBody注解返回的JSON对象类
 *
 * @author upex-team
 * @date 2019/12/30
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResponseResult<T> implements Serializable {

    /**
     * 200成功
     */
    private String httpCode = "200";

    /**
     * 00000表示成功，>0表示失败,<0系统保留
     */
    private String code;

    /**
     * 提示信息
     */
    private String msg;

    /**
     * 系统时间
     */
    private Long requestTime;

    /**
     * 返回数据
     */
    private T data;

    public boolean isSuccess() {
        return "00000".equals(code);
    }

    public <V> V toBean(Class<V> targetType){
        if (getData() == null){
            return null;
        }
        return BeanUtil.toBean(this.getData(), targetType, CopyOptions.create().ignoreError().ignoreCase());
    }


    public <V> List<V> toList(Class<V> targetType){
        if (getData() == null) {
            return Collections.emptyList();
        }
        if (!(getData() instanceof Collection)) {
            return Collections.emptyList();
        }
        Collection<?> data = (Collection<?>) this.getData();
        return BeanUtil.copyToList(data, targetType, CopyOptions.create().ignoreError().ignoreCase());
    }

    public Map<String,Object> toMap(){
        if (getData() == null) {
            return Collections.emptyMap();
        }
        return BeanUtil.beanToMap(getData());
    }

    public JSONObject toJSONObject(){
        if (getData() == null) {
            return new JSONObject();
        }
        Object json = JSON.toJSON(getData());
        if (json instanceof JSONObject) {
            return (JSONObject) json;
        }
        return new JSONObject();
    }

}
