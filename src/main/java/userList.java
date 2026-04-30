//названия функции
public interface userList {
    User get(int index);
    void add(User user);
    boolean remove(User user);
    boolean removeAt(int index);
    int size();
    void clear();
}
