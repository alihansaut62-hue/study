import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ArrayListTest {
    private ArrayList carList;

    @Before
    public void setUp() {
        carList = new ArrayList();
    }

    @After
    public void tearDown() {
        carList.clear();
    }

    @Test
    public void testAddSingleCar() {
        Car car = new Car("BMW", 2020);
        carList.add(car);
        assertEquals(1, carList.size());
        assertEquals(car, carList.get(0));
    }

    @Test
    public void testAddMultipleCars() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);
        Car car3 = new Car("Audi", 2022);

        carList.add(car1);
        carList.add(car2);
        carList.add(car3);

        assertEquals(3, carList.size());
        assertEquals(car1, carList.get(0));
        assertEquals(car2, carList.get(1));
        assertEquals(car3, carList.get(2));
    }

    @Test
    public void testGetCar() {
        Car car = new Car("Tesla", 2023);
        carList.add(car);
        assertEquals(car, carList.get(0));
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void testGetInvalidIndex() {
        carList.add(new Car("BMW", 2020));
        carList.get(5);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void testGetNegativeIndex() {
        carList.add(new Car("BMW", 2020));
        carList.get(-1);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void testGetEmptyList() {
        carList.get(0);
    }

    @Test
    public void testSizeEmpty() {
        assertEquals(0, carList.size());
    }

    @Test
    public void testSizeAfterAdd() {
        carList.add(new Car("BMW", 2020));
        carList.add(new Car("Mercedes", 2021));
        assertEquals(2, carList.size());
    }

    @Test
    public void testRemoveExistingCar() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);
        carList.add(car1);
        carList.add(car2);

        assertTrue(carList.remove(car1));
        assertEquals(1, carList.size());
        assertEquals(car2, carList.get(0));
    }

    @Test
    public void testRemoveNonExistingCar() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);
        carList.add(car1);

        assertFalse(carList.remove(car2));
        assertEquals(1, carList.size());
    }

    @Test
    public void testRemoveFromEmptyList() {
        Car car = new Car("BMW", 2020);
        assertFalse(carList.remove(car));
    }

    @Test
    public void testRemoveAtValidIndex() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);
        Car car3 = new Car("Audi", 2022);

        carList.add(car1);
        carList.add(car2);
        carList.add(car3);

        assertTrue(carList.removeAt(1));
        assertEquals(2, carList.size());
        assertEquals(car1, carList.get(0));
        assertEquals(car3, carList.get(1));
    }

    @Test
    public void testRemoveAtFirstIndex() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);

        carList.add(car1);
        carList.add(car2);

        assertTrue(carList.removeAt(0));
        assertEquals(1, carList.size());
        assertEquals(car2, carList.get(0));
    }

    @Test
    public void testRemoveAtLastIndex() {
        Car car1 = new Car("BMW", 2020);
        Car car2 = new Car("Mercedes", 2021);

        carList.add(car1);
        carList.add(car2);

        assertTrue(carList.removeAt(1));
        assertEquals(1, carList.size());
        assertEquals(car1, carList.get(0));
    }

    @Test
    public void testRemoveAtInvalidIndex() {
        Car car = new Car("BMW", 2020);
        carList.add(car);

        assertFalse(carList.removeAt(5));
        assertFalse(carList.removeAt(-1));
    }

    @Test
    public void testRemoveAtEmptyList() {
        assertFalse(carList.removeAt(0));
    }

    @Test
    public void testClearNonEmptyList() {
        carList.add(new Car("BMW", 2020));
        carList.add(new Car("Mercedes", 2021));
        carList.add(new Car("Audi", 2022));

        carList.clear();
        assertEquals(0, carList.size());
    }

    @Test
    public void testClearEmptyList() {
        carList.clear();
        assertEquals(0, carList.size());
    }

    @Test
    public void testArrayResizing() {
        for (int i = 0; i < 15; i++) {
            carList.add(new Car("Car" + i, 2000 + i));
        }

        assertEquals(15, carList.size());

        for (int i = 0; i < 15; i++) {
            Car car = carList.get(i);
            assertEquals("Car" + i, car.getBrand());
            assertEquals(2000 + i, car.getNamer());
        }
    }

    @Test
    public void testComplexOperations() {
        Car bmw = new Car("BMW", 2020);
        Car mercedes = new Car("Mercedes", 2021);
        Car audi = new Car("Audi", 2022);

        carList.add(bmw);
        carList.add(mercedes);
        carList.add(audi);
        assertEquals(3, carList.size());

        carList.removeAt(1);
        assertEquals(2, carList.size());

        Car tesla = new Car("Tesla", 2023);
        carList.add(tesla);
        assertEquals(3, carList.size());

        carList.remove(bmw);
        assertEquals(2, carList.size());

        assertEquals(audi, carList.get(0));
        assertEquals(tesla, carList.get(1));
    }
}
