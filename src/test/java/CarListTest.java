import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class CarListTest {
    private CarList carList;

    @Before
    public void setUp() {
        carList = new ArrayList();
    }

    @Test
    public void testImplementsCarList() {
        assertNotNull(carList);
        assertEquals(0, carList.size());
    }

    @Test
    public void testAddAndGetViaInterface() {
        Car bmw = new Car("BMW", 2020);
        carList.add(bmw);

        assertEquals(1, carList.size());
        assertEquals(bmw, carList.get(0));
    }

    @Test
    public void testRemoveViaInterface() {
        Car bmw = new Car("BMW", 2020);
        Car audi = new Car("Audi", 2022);
        carList.add(bmw);
        carList.add(audi);

        assertTrue(carList.remove(bmw));
        assertEquals(1, carList.size());
        assertEquals(audi, carList.get(0));
    }

    @Test
    public void testClearViaInterface() {
        carList.add(new Car("BMW", 2020));
        carList.add(new Car("Mercedes", 2021));
        assertEquals(2, carList.size());

        carList.clear();
        assertEquals(0, carList.size());
    }
}
