import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class JavaCarListTest {

    private javaCarList carList;

    @Before
    public void setUp() {
        carList = new javaCar();
        for (int i = 0; i < 100; i++) {
            carList.add(new Car("brent" + i, i));
        }
    }

    @Test
    public void shouldAdd100Elements() {
        assertEquals(100, carList.size());
    }

    @Test
    public void shouldRemoveElementByIndex() {
        assertEquals(100, carList.size());

        assertTrue(carList.removeAt(5));

        assertEquals(99, carList.size());
        assertEquals("brent6", carList.get(5).getBrand());
    }

    @Test
    public void shouldRemoveElementByValue() {
        Car car = new Car("brent", 20);
        carList.add(car);
        assertEquals(101, carList.size());

        assertTrue(carList.remove(car));
        assertEquals(100, carList.size());
    }

    @Test
    public void shouldReturnFalseWhenRemovingMissingValue() {
        Car car = new Car("brent", 20);
        assertFalse(carList.remove(car));
        assertEquals(100, carList.size());
    }

    @Test
    public void shouldClearList() {
        carList.clear();
        assertEquals(0, carList.size());
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowWhenIndexOutOfBounds() {
        carList.get(100);
    }

    @Test
    public void shouldGetFirstElement() {
        Car car = carList.get(0);
        assertEquals("brent0", car.getBrand());
    }
}

