package dev.yuizho.login_demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTests {

    @Autowired
    MockMvc mockMvc;

    @Test
    void 未ログインでルートにアクセスするとログイン画面にリダイレクトされる() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void 未ログインでloggedinにアクセスするとログイン画面にリダイレクトされる() throws Exception {
        mockMvc.perform(get("/loggedin"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @WithMockUser
    void ログイン済みならルートが表示される() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk());
    }

    @Test
    void ログイン画面は未ログインでも表示される() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());
    }

    @Test
    void ヘルスチェックは未ログインでもアクセスできる() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void 正しい認証情報でログインするとloggedinにリダイレクトされる() throws Exception {
        mockMvc.perform(formLogin("/login").user("user1").password("password"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/loggedin"));
    }
}
