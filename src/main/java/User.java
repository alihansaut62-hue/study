//логика функции
public class User implements userList{

    String name;
    int age;

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }



    @Override
    public User get(int index) {
        return null;
    }

    @Override
    public void add(User user) {

    }

    @Override
    public boolean remove(User user) {
        return false;
    }

    @Override
    public boolean removeAt(int index) {
        return false;
    }

    @Override
    public int size() {
        return 0;
    }

    @Override
    public void clear() {

    }
}