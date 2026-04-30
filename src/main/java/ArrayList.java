import java.util.Arrays;

public class ArrayList implements CarList {
    private Car[] cars;
    private int size;
    private static final int INITIAL_CAPACITY = 10;

    public ArrayList() {
        cars = new Car[INITIAL_CAPACITY];
        size = 0;
    }

    @Override
    public Car get(int index) {
        if (index < 0 || index >= size) {
            throw new IndexOutOfBoundsException("Index: " + index + ", Size: " + size);
        }
        return cars[index];
    }

    @Override
    public void add(Car car) {
        if (size == cars.length) {
            resize();
        }
        cars[size++] = car;
    }

    @Override
    public boolean remove(Car car) {
        for (int i = 0; i < size; i++) {
            if (cars[i] != null
                    && cars[i].getBrand().equals(car.getBrand())
                    && cars[i].getNamer() == car.getNamer()) {
                removeAt(i);
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean removeAt(int index) {
        if (index < 0 || index >= size) {
            return false;
        }
        for (int i = index; i < size - 1; i++) {
            cars[i] = cars[i + 1];
        }
        cars[--size] = null;
        return true;
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public void clear() {
        cars = new Car[INITIAL_CAPACITY];
        size = 0;
    }

    private void resize() {
        cars = Arrays.copyOf(cars, cars.length * 2);
    }
}
