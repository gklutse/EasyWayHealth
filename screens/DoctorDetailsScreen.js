// screens/DoctorDetailsScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function DoctorDetailsScreen({ route, navigation }) {
  const { doctor } = route.params;

  return (
    <View style={styles.container}>
      <Text>{doctor.name}</Text>
      <Text>{doctor.specialty}</Text>
      <Button title="Book Appointment" onPress={() => navigation.navigate('AppointmentConfirmation', { doctor })} />
      <Button title="Back" onPress={() => navigation.goBack()} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
});
