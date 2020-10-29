/*
 <notice>

 Copyright 2017 IBM Corporation

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 </notice>
 */

package com.ibm.devops.notification;

import com.ibm.devops.dra.Util;
import hudson.EnvVars;
import hudson.model.Job;
import hudson.model.Run;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.http.StatusLine;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.mockito.Mockito.*;
import static junit.framework.TestCase.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Jenkins.class, Job.class, HttpClients.class, CloseableHttpResponse.class})
public class MessageHandlerTest {
    private Jenkins jenkins = mock(Jenkins.class);

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getRootUrl()).thenReturn("http://localhost:1234/");
    }

    @Test
    public void testBuildMessage() {
        String phase = "COMPLETED";
        String result = "SUCCESS";

        Run r = mock(Run.class);
        EnvVars envVars = mock(EnvVars.class);
        Job job = PowerMockito.mock(Job.class);

        when(r.getParent()).thenReturn(job);
        when(r.getNumber()).thenReturn(0);
        when(r.getQueueId()).thenReturn((long)0);
        when(r.getUrl()).thenReturn("job/test/1/");
        when(r.getDuration()).thenReturn((long)0);
        when(job.getDisplayName()).thenReturn("test");
        when(job.getUrl()).thenReturn("job/test/");
        when(envVars.get("GIT_COMMIT")).thenReturn("commit");
        when(envVars.get("GIT_BRANCH")).thenReturn("branch");
        when(envVars.get("GIT_PREVIOUS_COMMIT")).thenReturn("previous");
        when(envVars.get("GIT_PREVIOUS_SUCCESSFUL_COMMIT")).thenReturn("previous_success");
        when(envVars.get("GIT_URL")).thenReturn("url");
        when(envVars.get("GIT_COMMITTER_NAME")).thenReturn("committer");
        when(envVars.get("GIT_COMMITTER_EMAIL")).thenReturn("committer_email");
        when(envVars.get("GIT_AUTHOR_NAME")).thenReturn("author");
        when(envVars.get("GIT_AUTHOR_EMAIL")).thenReturn("author_email");

        JSONObject message = new JSONObject();
        JSONObject build = new JSONObject();
        JSONObject scm = new JSONObject();

        scm.put("git_commit", envVars.get("GIT_COMMIT"));
        scm.put("git_branch", envVars.get("GIT_BRANCH"));
        scm.put("git_previous_commit", envVars.get("GIT_PREVIOUS_COMMIT"));
        scm.put("git_previous_successful_commit", envVars.get("GIT_PREVIOUS_SUCCESSFUL_COMMIT"));
        scm.put("git_url", envVars.get("GIT_URL"));
        scm.put("git_committer_name", envVars.get("GIT_COMMITTER_NAME"));
        scm.put("git_committer_email", envVars.get("GIT_COMMITTER_EMAIL"));
        scm.put("git_author_name", envVars.get("GIT_AUTHOR_NAME"));
        scm.put("git_author_email", envVars.get("GIT_AUTHOR_EMAIL"));

        build.put("number", r.getNumber());
        build.put("queue_id", r.getQueueId());
        build.put("phase", phase);
        build.put("url", r.getUrl());
        build.put("full_url", Jenkins.getInstance().getRootUrl() + r.getUrl());
        build.put("status", result);
        build.put("duration", r.getDuration());
        build.put("scm", scm);
        message.put("name", job.getDisplayName());
        message.put("url", job.getUrl());
        message.put("build", build);

        assertEquals(message, MessageHandler.buildMessage(r, envVars, phase, result));

        build.put("scm", new JSONObject());
        message.put("build", build);

        assertEquals(message, MessageHandler.buildMessage(r, null, phase, result));
    }

    @Test
    public void testPostToWebhook() throws IOException {
    	HttpClientBuilder httpClientBuilder = PowerMockito.mock(HttpClientBuilder.class);
        CloseableHttpClient httpClient = PowerMockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse response = PowerMockito.mock(CloseableHttpResponse.class);
        PowerMockito.mockStatic(HttpClients.class);
        StatusLine statusLine = mock(StatusLine.class);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(baos);
        String content;
        JSONObject message = new JSONObject();
        
        RequestConfig defaultRequestConfig = RequestConfig.custom()
    		    .setSocketTimeout(5000)
    		    .setConnectTimeout(5000)
    		    .setConnectionRequestTimeout(5000)
    		    .build();
        when(HttpClients.custom()).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setDefaultRequestConfig(defaultRequestConfig).build()).thenReturn(httpClient);
        when(httpClient.execute(any(HttpPost.class))).thenReturn(response);
        when(response.getStatusLine()).thenReturn(statusLine);
        when(statusLine.toString()).thenReturn("200");

        assertTrue(Util.isNullOrEmpty(""));
        assertTrue(Util.isNullOrEmpty(null));

        MessageHandler.postToWebhook("", false, message, printStream);
        content = new String(baos.toByteArray(), StandardCharsets.UTF_8);

        assertTrue(content.contains("[IBM Cloud DevOps] IBM_CLOUD_DEVOPS_WEBHOOK_URL not set."));

        MessageHandler.postToWebhook("http://fakewebhook", false, message, printStream);
        content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        assertTrue(content.contains("[IBM Cloud DevOps] Message successfully posted to webhook."));

        when(statusLine.toString()).thenReturn("400");
        MessageHandler.postToWebhook("http://fakewebhook", false, message, printStream);
        content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        assertTrue(content.contains("[IBM Cloud DevOps] Message failed, response status:"));

        when(httpClient.execute(any(HttpPost.class))).thenThrow(new IOException("..."));
        MessageHandler.postToWebhook("http://fakewebhook", false, message, printStream);
        content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        assertTrue(content.contains("[IBM Cloud DevOps] IOException, could not post to webhook:"));
    }
     
    @Test
    public void testPostDeployableMessageToWebhook() throws IOException {
    	HttpClientBuilder httpClientBuilder = PowerMockito.mock(HttpClientBuilder.class);
    	CloseableHttpClient httpClient = PowerMockito.mock(CloseableHttpClient.class);
    	CloseableHttpResponse response = PowerMockito.mock(CloseableHttpResponse.class);
    	PowerMockito.mockStatic(HttpClients.class);
    	StatusLine statusLine = mock(StatusLine.class);
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	PrintStream printStream = new PrintStream(baos);
    	String content;
    	JSONObject message = new JSONObject();

    	RequestConfig defaultRequestConfig = RequestConfig.custom()
    		    .setSocketTimeout(5000)
    		    .setConnectTimeout(5000)
    		    .setConnectionRequestTimeout(5000)
    		    .build();
        when(HttpClients.custom()).thenReturn(httpClientBuilder);
        when(httpClientBuilder.setDefaultRequestConfig(defaultRequestConfig).build()).thenReturn(httpClient);
    	when(httpClient.execute(any(HttpPost.class))).thenReturn(response);
    	when(response.getStatusLine()).thenReturn(statusLine);
    	when(statusLine.toString()).thenReturn("200");

    	assertTrue(Util.isNullOrEmpty(""));
    	assertTrue(Util.isNullOrEmpty(null));

    	MessageHandler.postToWebhook("", true, message, printStream);
    	content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	System.out.println("content: " + content);
    	assertTrue(content.contains("[IBM Cloud DevOps] IBM_CLOUD_DEVOPS_WEBHOOK_URL not set."));

    	MessageHandler.postToWebhook("http://fakewebhook", true, message, printStream);
    	content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	assertTrue(content.contains("[IBM Cloud DevOps] Message successfully posted to webhook."));

    	when(statusLine.toString()).thenReturn("400");
    	MessageHandler.postToWebhook("http://fakewebhook", true, message, printStream);
    	content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	assertTrue(content.contains("[IBM Cloud DevOps] Message failed, response status:"));

    	when(httpClient.execute(any(HttpPost.class))).thenThrow(new IOException("..."));
    	MessageHandler.postToWebhook("http://fakewebhook", true, message, printStream);
    	content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	assertTrue(content.contains("[IBM Cloud DevOps] IOException, could not post to webhook:"));
    	
    	message = new JSONObject();
    	message.put("Org" , "{\"Name\": \"darth_vador@ibm.com\", \"Guid\": \"1b45b640-ff52-4f94-8009-9af44aa9f9c8\"}");
    	message.put("Space" , "{\"Name\": \"dev\", \"Guid\": \"838b41a6-58e0-4c05-aaf4-817925d42332\"}");
    	message.put("App" , "{\"Name\": \"node-hello-world\", \"Guid\": \"a7820d14-9d5d-40c7-a58c-43caeaf8cb75\"}");
    	message.put("ApiEndpoint" , "https://api.stage1.ng.bluemix.net");
    	message.put("Method" , "POST");
    	message.put("GitData" , "[{\"GitURL\": \"https://github.com/dvador/simple-node-app.git\", \"GitBranch\": \"origin/master\", \"GitCommitID\": \"590c229c64ef246e5742744449963dc74493cb8a\"}]");
    	
    	when(httpClient.execute(any(HttpPost.class))).thenReturn(response);
    	MessageHandler.postToWebhook("http://fakewebhook", true, message, printStream);
    	content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	assertTrue(content.contains("[IBM Cloud DevOps] Message successfully posted to webhook."));
    }
}
