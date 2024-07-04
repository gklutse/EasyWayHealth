// screens/NotificationsScreen.js
import React from 'react';
import { View, Text, FlatList, Button, StyleSheet } from 'react-native';

const notifications = [
  { id: '1', message: 'Your appointment with Dr. John Doe is confirmed.' },
  { id: '2', message: 'New job posting: Nurse needed at City Hospital.' },
  // Add more notifications here
];

export default function NotificationsScreen({ navigation }) {
  const renderItem = ({ item }) => (
    <View style={styles.item}>
      <Text>{item.message}</Text>
      <Button title="Dismiss" onPress={() => {/* Implement dismiss logic here */}} />
    </View>
  );

  return (
    <View style={styles.container}>
      <Text>Notifications</Text>
      <FlatList
        data={notifications}
        renderItem={renderItem}
        keyExtractor={(item) => item.id}
      />
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
  item: {
    backgroundColor: '#f9c2ff',
    padding: 20,
    marginVertical: 8,
    marginHorizontal: 16,
  },
});
