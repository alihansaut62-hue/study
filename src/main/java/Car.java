public class Car {
    private String brand;
    private int namer;

    public Car(String brand, int namer) {
        this.brand = brand;
        this.namer = namer;
    }

    public String getBrand() {
        return brand;
    }

    public int getNamer() {
        return namer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Car car = (Car) o;
        if (namer != car.namer) return false;
        return brand != null ? brand.equals(car.brand) : car.brand == null;
    }

    @Override
    public int hashCode() {
        int result = brand != null ? brand.hashCode() : 0;
        result = 31 * result + namer;
        return result;
    }
}
