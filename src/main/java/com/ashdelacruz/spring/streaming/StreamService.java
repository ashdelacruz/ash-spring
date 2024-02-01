package com.ashdelacruz.spring.streaming;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class StreamService {

    @Autowired
    private ResourceLoader resourceLoader;
    // private static final String DEMO_FILE_PATH = "classpath:media/album_cover_demo_copy.mp4";
    private static final String SAMPLE_FILE_PATH = "classpath:media/sample-5s.mp4";
    // private static final String FILE_PATH = "classpath:media/BlackAdam(2022).mkv";
    // private static final String FILE_PATH = "classpath:media//%s.mp4";

  
    public Mono<Resource> retrieveContent(String title) {

        // String FILE_PATH;

        System.out.println("TESTING 2!!! title = " + title);


        // if(title == "demo") {
        //     FILE_PATH = DEMO_FILE_PATH;
        // } else {
        //     FILE_PATH = SAMPLE_FILE_PATH;
        // }

        
        
        // return Mono.fromSupplier(() -> 
        // resourceLoader
        // .getResource(
        //     FILE_PATH
        //     ));
        return Mono.fromSupplier(() -> resourceLoader.getResource(SAMPLE_FILE_PATH));
    }
    
}
