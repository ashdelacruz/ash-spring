package com.ashdelacruz.spring.controllers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.bson.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.payload.request.UserModRequest;
import com.ashdelacruz.spring.security.services.ResponseService;
import com.ashdelacruz.spring.security.services.UserModService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

// @CrossOrigin(origins = "http://localhost:80", maxAge = 3600, allowCredentials = "true")

@RestController
@RequestMapping("/api/demo")
@Slf4j
public class DemoController {

    @Autowired
    ResponseService responseService;

    @Value("classpath:static/demoUserList.json")
    Resource demoUserList;

    // @Autowired
    // UserModService userModService;
    // Demo Mode

    /**
     * 
     * @return a list of all user info, not including passwords
     */
    @GetMapping("/user/list")
    public ResponseEntity<?> demoGetUserList() {
        log.info("");
        String demoUserListStr = "";
    //     try {
    //         // log.info("demoUserList = {}", demoUserList.getFile());
    //         // log.info("demoUserList = {}", demoUserList.getContentAsString(StandardCharsets.UTF_8));
    //         // demoUserListStr = demoUserList.getContentAsString(StandardCharsets.UTF_8);

    //         File resource = ResourceUtils.getFile(
    //   "classpath:static/demoUserList.json");
    //             // log.info("demoUserList = {}", demoUserList.getContentAsString(StandardCharsets.UTF_8));
          
    //         demoUserListStr = new String(
    //                 Files.readAllBytes(resource.toPath()));
    //                 log.info("demoUserList = {}", demoUserListStr);


          

    //     } catch (IOException e) {
    //         // TODO Auto-generated catch block
    //         e.printStackTrace();
    //     }
    // = new ArrayList<ResponseUser>();
            Resource resource = new ClassPathResource("/static/json/beers.json");
       
                   // read json and write to db
            ObjectMapper mapper = new ObjectMapper();
            log.info("mapper created");
            
            TypeReference<List<UserDetails>> typeReference = new TypeReference<List<UserDetails>>(){};
            InputStream inputStream = TypeReference.class.getResourceAsStream("/static/demoUserList.json");
            
            log.info("inputStream");
            try {
                List<UserDetails> users = mapper.readValue(inputStream,typeReference);
                log.info("users = {}", Arrays.toString(users.toArray()));
            
                // userService.save(users);
                System.out.println("Users Saved!");
            } catch (IOException e){
                System.out.println("Unable to save users: " + e.getMessage());
            }
       
        //     try {
        //     ObjectMapper mapper = new ObjectMapper();
        //     List<ResponseUser> respUsers =  mapper.readValue(demoUserList.getInputStream(), new TypeReference<List<ResponseUser>>(){});
        //     log.info("respUsers = {}", Arrays.toString(respUsers.toArray()));
        //     log.info("demoUserListStr = {}", demoUserListStr);
      
      
        //     Map<String, List<ResponseUser>> responseData = new HashMap<String, List<ResponseUser>>();
        //     responseData.put("users", respUsers);
        //     log.info("mapping responseUsers to responseData");
    
        //     ResponseEntity<Object> response = this.responseService.generateResponse("Request Successful", HttpStatus.OK,
        //             responseData);
        //     log.info("RETURN response = {}", response.toString());
        //     return response;


            
    
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
        // return null;
       
        ResponseEntity<Object> response = this.responseService.generateResponse("Request Successful", HttpStatus.OK,
        null);
log.info("RETURN response = {}", response.toString());
return response;

    }

    // /**
    // *
    // * @return a list of all user info, not including passwords
    // */
    // @GetMapping("/demo/user/info")
    // @PreAuthorize("hasRole('ADMIN')")
    // public ResponseEntity<?> demoGetUserInfo(@Valid @RequestBody UserModRequest
    // userInfoRequest) {
    // log.info("");

    // if ((userInfoRequest.getIds() == null || userInfoRequest.getIds().isEmpty())
    // &&
    // (userInfoRequest.getUsernames() == null ||
    // userInfoRequest.getUsernames().isEmpty()) &&
    // (userInfoRequest.getEmails() == null ||
    // userInfoRequest.getEmails().isEmpty())) {
    // ResponseEntity<Object> response =
    // this.responseService.generateResponse("Request contains no user info.",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;
    // }

    // return this.userModService.getUserInfo(userInfoRequest.getIds(),
    // userInfoRequest.getUsernames(),
    // userInfoRequest.getEmails());

    // }

    // @PostMapping("/demo/user/resend")
    // @PreAuthorize("hasRole('MODERATOR')")
    // public ResponseEntity<?> demoResend(@Valid @RequestBody UserModRequest
    // resendRequest) {
    // log.info("");

    // if (resendRequest.getIds() == null || resendRequest.getIds().isEmpty()) {
    // ResponseEntity<Object> response = this.responseService.generateResponse("ids
    // required",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;

    // }

    // return
    // this.userModService.resendAccountActivationLink(resendRequest.getIds());

    // }

    // /**
    // * Changes a User's roles
    // *
    // * @param roleRequest
    // * @return
    // */
    // @PutMapping("/demo/user/roles")
    // @PreAuthorize("hasRole('MODERATOR')")
    // public ResponseEntity<?> demoSetUserRole(@Valid @RequestBody UserModRequest
    // roleRequest) {
    // log.info("");

    // if (roleRequest.getIds() == null || roleRequest.getIds().isEmpty()) {
    // ResponseEntity<Object> response = this.responseService.generateResponse("ids
    // required",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;

    // }

    // if (roleRequest.getNewRole() == null ||
    // roleRequest.getNewRole().toString().isEmpty()) {
    // ResponseEntity<Object> response =
    // this.responseService.generateResponse("newRole required",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;

    // }

    // return this.userModService.setRole(roleRequest.getIds(),
    // roleRequest.getNewRole());

    // }

    // /**
    // * Changes User(s) status
    // * Expects a list of user IDs that are all the same status,
    // * then their status set to the newStatus
    // *
    // * @param userStatusRequest A list of user IDs, and the new status to set for
    // * the user(s)
    // * @return
    // */
    // @PutMapping("/demo/user/status")
    // @PreAuthorize("hasRole('MODERATOR')")
    // public ResponseEntity<?> demoSetUserStatus(@Valid @RequestBody UserModRequest
    // userStatusRequest) {

    // log.info("");
    // ResponseEntity<Object> response;
    // if (userStatusRequest.getIds() == null ||
    // userStatusRequest.getIds().isEmpty()) {
    // response = this.responseService.generateResponse("ids required",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;
    // }

    // // Check status is valid
    // if (userStatusRequest.getNewStatus() != 0 && userStatusRequest.getNewStatus()
    // != 1) {
    // response = this.responseService.generateResponse(
    // "newStatus \"" + userStatusRequest.getNewStatus() + "\" is invalid",
    // HttpStatus.UNPROCESSABLE_ENTITY, null);
    // log.error(" RETURN response = {} ", response.toString());
    // return response;
    // }
    // log.info(" newStatus is valid");

    // return this.userModService.setStatus(userStatusRequest.getIds(),
    // userStatusRequest.getNewStatus());
    // }

    // /**
    // * Changes a User's roles
    // *
    // * @param deleteRequest
    // * @return
    // */
    // @DeleteMapping("/demo/user/delete")
    // @PreAuthorize("hasRole('ADMIN')")
    // public ResponseEntity<?> demoDeleteUser(@Valid @RequestBody UserModRequest
    // deleteRequest) {

    // log.info("");

    // if (deleteRequest.getIds() == null || deleteRequest.getIds().isEmpty()) {
    // ResponseEntity<Object> response = this.responseService.generateResponse("ids
    // required",
    // HttpStatus.BAD_REQUEST, null);
    // log.error(" RETURN response = {}", response.toString());
    // return response;
    // }

    // return this.userModService.deleteUser(deleteRequest.getIds());

    // }
}
