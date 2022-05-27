package com.cydeo.entity;

import com.cydeo.entity.common.UserPrincipal;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import java.time.LocalDateTime;

@Component
public class BaseEntityListener extends AuditingEntityListener {

    public void onPrePersist(BaseEntity baseEntity){

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        baseEntity.setInsertDateTime(LocalDateTime.now());
        baseEntity.setLastUpdateDateTime(LocalDateTime.now());

        if(authentication != null && !authentication.getName().equals("anonymousUser")) {
            Object principal = authentication.getPrincipal();
            baseEntity.setInsertUserId(((UserPrincipal) principal).getId());
            baseEntity.setLastUpdateUserId(((UserPrincipal) principal).getId());
        }
    }

    public void onPreUpdate(BaseEntity baseEntity){

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        baseEntity.setLastUpdateDateTime(LocalDateTime.now());

        if(authentication != null && !authentication.getName().equals("anonymousUser")) {
            Object principal = authentication.getPrincipal();
            baseEntity.setLastUpdateUserId(((UserPrincipal) principal).getId());
        }

    }
}
