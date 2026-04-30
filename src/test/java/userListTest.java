import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class userListTest {

    private userList userList;

    @Before
    public void setUp() throws Exception {
        userList = new userList();
        for (int i = 0 ; i < 100; i++){
            userList.add(new User("naim"+ i,i));
        }
    }

    @Test
    public void get() {
    }

    @Test
    public void add() {
        assertEquals(100, userList.size());
    }

    @Test
    public void remove() {
    }

    @Test
    public void removeAt() {
    }

    @Test
    public void size() {
    }

    @Test
    public void clear() {
    }
}